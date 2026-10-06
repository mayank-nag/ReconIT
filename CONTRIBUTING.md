# Contributing to ReconIT (Venom)

Thank you for your interest in contributing to **ReconIT / Venom**! We welcome bug reports, module improvements, documentation enhancements, and security hardening PRs.

---

## Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/mayank-nag/ReconIT.git
cd ReconIT
```

### 2. Set Up Virtual Environment

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### 3. Running Tests

```bash
pytest
```

### 4. Code Quality & Linting

We use `ruff` for linting and code formatting:

```bash
ruff check .
ruff format .
```

And `mypy` for static type checking:

```bash
mypy core modules report venom.py
```

---

## Coding Standards

- **Low-Impact & Safe:** Modules should avoid disruptive payloads or intrusive brute-force loops. Always adhere to rate-limiting and scope boundaries.
- **Defensive Parsing:** All external responses, documents (PDF/images), and target headers must be treated as untrusted and parsed defensively.
- **Privacy:** Never log, store, or output plaintext credentials or secret tokens. Use `core.target.mask_secret` for discovered secrets.
- **Single HTTP Library:** All HTTP networking must standardize on `httpx` and utilize `core.http_client.HttpClient` to respect the global rate limiter.

---

## Submitting Pull Requests

1. Create a descriptive feature branch: `git checkout -b feature/my-enhancement`
2. Ensure existing and new tests pass: `pytest`
3. Commit your changes with clear commit messages: `git commit -m "Add X capability to module Y"`
4. Push to your fork and submit a Pull Request to `main`.
