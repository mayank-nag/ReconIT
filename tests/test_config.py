"""Unit tests for configuration loading and CLI argument precedence."""

import tempfile
import argparse
from pathlib import Path
import pytest
from venom import load_config, merge_options


def test_load_config_missing_default():
    # If default config path doesn't exist, returns empty dict
    cfg = load_config("non_existent_config_12345.yaml", is_default_path=True)
    assert cfg == {}


def test_load_config_missing_custom_fails():
    # If user specifies a non-existent config file, raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        load_config("missing_custom_file.yaml", is_default_path=False)


def test_load_config_malformed_yaml_fails():
    # Malformed YAML must fail loudly with ValueError
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write("invalid: yaml: [broken syntax\n  key: value")
        temp_path = f.name

    try:
        with pytest.raises(ValueError, match="Malformed YAML"):
            load_config(temp_path, is_default_path=False)
    finally:
        Path(temp_path).unlink()


def test_load_config_valid_yaml():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write("scan:\n  timeout: 45\n  rate_limit: 10.0\n")
        temp_path = f.name

    try:
        cfg = load_config(temp_path, is_default_path=False)
        assert cfg["scan"]["timeout"] == 45
        assert cfg["scan"]["rate_limit"] == 10.0
    finally:
        Path(temp_path).unlink()


def test_merge_options_precedence():
    # Scenario 1: CLI provides value, config provides value -> CLI wins
    cli_args = argparse.Namespace(
        full=True,
        no_crawl=False,
        depth=5,
        max_subdomains=200,
        timeout=25,
        rate_limit=8.0,
        output="./custom_out/",
        format="json",
        ignore_robots=False,
        verbose=True,
        quiet=False,
        log_file="test.log",
        scope="allowed.txt",
        dry_run=True,
        diff=None,
        recursive=False,
    )
    config = {
        "scan": {
            "crawl_depth": 2,
            "max_subdomains": 50,
            "timeout": 15,
            "rate_limit": 2.0,
        },
        "output": {
            "directory": "./config_out/",
            "format": "html",
        },
    }
    opts = merge_options(cli_args, config)
    assert opts["crawl_depth"] == 5  # CLI won
    assert opts["max_subdomains"] == 200  # CLI won
    assert opts["timeout"] == 25  # CLI won
    assert opts["rate_limit"] == 8.0  # CLI won
    assert opts["output_dir"] == "./custom_out/"  # CLI won
    assert opts["output_format"] == "json"  # CLI won

    # Scenario 2: CLI provides None -> config wins
    cli_args_none = argparse.Namespace(
        full=False,
        no_crawl=False,
        depth=None,
        max_subdomains=None,
        timeout=None,
        rate_limit=None,
        output=None,
        format=None,
        ignore_robots=False,
        verbose=False,
        quiet=False,
        log_file=None,
        scope=None,
        dry_run=False,
        diff=None,
        recursive=False,
    )
    opts2 = merge_options(cli_args_none, config)
    assert opts2["crawl_depth"] == 2  # Config won
    assert opts2["max_subdomains"] == 50  # Config won
    assert opts2["timeout"] == 15  # Config won
    assert opts2["rate_limit"] == 2.0  # Config won
    assert opts2["output_dir"] == "./config_out/"  # Config won
    assert opts2["output_format"] == "html"  # Config won

    # Scenario 3: Neither CLI nor config provides value -> built-in defaults win
    opts3 = merge_options(cli_args_none, {})
    assert opts3["crawl_depth"] == 3  # Built-in default
    assert opts3["max_subdomains"] == 100  # Built-in default
    assert opts3["timeout"] == 10  # Built-in default
    assert opts3["rate_limit"] == 5.0  # Built-in default
    assert opts3["output_dir"] == "./output/"  # Built-in default
    assert opts3["output_format"] == "all"  # Built-in default
