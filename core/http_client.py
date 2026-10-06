"""
Shared HTTP Client and Rate Limiting for Venom OSINT Framework.

Provides centralized request execution with:
- Shared global rate limiting across all modules
- Automatic retry with exponential backoff on 429/transient errors
- In-memory response caching for duplicate calls
- Standardized User-Agent and headers
"""

import time
import threading
import logging
from typing import Optional, Dict, Any, Tuple
import httpx

logger = logging.getLogger("venom.http")


class RateLimiter:
    """Thread-safe rate limiter implementing token bucket / leaky bucket pacing."""

    def __init__(self, requests_per_second: float = 5.0):
        self.rate = max(0.1, float(requests_per_second))
        self.interval = 1.0 / self.rate
        self.lock = threading.Lock()
        self.last_request_time = 0.0

    def wait(self) -> None:
        """Block until next request window is available."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_request_time
            if elapsed < self.interval:
                sleep_time = self.interval - elapsed
                time.sleep(sleep_time)
            self.last_request_time = time.monotonic()


class HttpClient:
    """Unified HTTP client with shared rate limiting, retries, and caching."""

    _instance: Optional["HttpClient"] = None
    _lock = threading.Lock()

    def __init__(
        self,
        rate_limit: float = 5.0,
        timeout: float = 10.0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        self.rate_limiter = RateLimiter(rate_limit)
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (Venom-OSINT)"
        )
        self.verify_ssl = verify_ssl
        self._cache: Dict[Tuple[str, str], Tuple[float, httpx.Response]] = {}
        self._cache_lock = threading.Lock()
        self._client: Optional[httpx.Client] = None

    @classmethod
    def get_instance(
        cls,
        rate_limit: float = 5.0,
        timeout: float = 10.0,
        user_agent: Optional[str] = None,
    ) -> "HttpClient":
        """Get or initialize singleton instance."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(
                    rate_limit=rate_limit,
                    timeout=timeout,
                    user_agent=user_agent,
                )
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (useful in tests)."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={"User-Agent": self.user_agent},
                follow_redirects=True,
            )
        return self._client

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None,
        max_retries: int = 3,
        use_cache: bool = False,
        cache_ttl: float = 300.0,
        stream: bool = False,
    ) -> httpx.Response:
        """Execute HTTP request with rate limiting, retries, and optional caching."""
        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)

        req_timeout = timeout if timeout is not None else self.timeout

        # Check cache for idempotent GET requests
        cache_key = (method.upper(), str(url) + str(sorted(params.items()) if params else ""))
        if use_cache and method.upper() == "GET":
            with self._cache_lock:
                if cache_key in self._cache:
                    cached_time, cached_resp = self._cache[cache_key]
                    if time.monotonic() - cached_time < cache_ttl:
                        return cached_resp

        attempt = 0
        backoff = 1.0

        while attempt <= max_retries:
            attempt += 1
            self.rate_limiter.wait()

            try:
                if stream:
                    # In streaming mode, return context or response
                    resp = self.client.send(
                        self.client.build_request(
                            method, url, params=params, headers=req_headers, json=json, data=data, timeout=req_timeout
                        ),
                        stream=True,
                    )
                else:
                    resp = self.client.request(
                        method,
                        url,
                        params=params,
                        headers=req_headers,
                        json=json,
                        data=data,
                        timeout=req_timeout,
                    )

                # Handle rate limit 429
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    sleep_time = float(retry_after) if retry_after and retry_after.isdigit() else backoff
                    logger.warning(
                        f"Rate limit hit (429) for {url}. Backing off for {sleep_time:.1f}s (attempt {attempt}/{max_retries})"
                    )
                    time.sleep(sleep_time)
                    backoff *= 2.0
                    continue

                if resp.status_code in (502, 503, 504) and attempt <= max_retries:
                    logger.warning(
                        f"Server error ({resp.status_code}) for {url}. Retrying in {backoff:.1f}s..."
                    )
                    time.sleep(backoff)
                    backoff *= 2.0
                    continue

                if use_cache and method.upper() == "GET" and resp.status_code == 200:
                    with self._cache_lock:
                        self._cache[cache_key] = (time.monotonic(), resp)

                return resp

            except (httpx.TimeoutException, httpx.NetworkError) as e:
                if attempt > max_retries:
                    logger.error(f"Request failed after {max_retries} retries for {url}: {e}")
                    raise
                logger.warning(
                    f"Network/timeout error for {url} ({e}). Retrying in {backoff:.1f}s (attempt {attempt}/{max_retries})..."
                )
                time.sleep(backoff)
                backoff *= 2.0

        raise httpx.RequestError(f"Failed to fetch {url} after {max_retries} retries")

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        """Close underlying client."""
        if self._client is not None and not self._client.is_closed:
            self._client.close()
