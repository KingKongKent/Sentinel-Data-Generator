"""Tests for the CLI entry point (__main__.py)."""

from sentinel_data_generator.__main__ import main, parse_args


class TestParseArgs:
    """Tests for CLI argument parsing."""

    def test_defaults(self) -> None:
        args = parse_args([])
        assert args.config.parts[-2:] == ("config", "config.yaml")
        assert args.output is None
        assert args.count is None
        assert args.log_level == "INFO"

    def test_custom_config(self) -> None:
        args = parse_args(["--config", "my/config.yaml"])
        assert args.config.parts[-2:] == ("my", "config.yaml")

    def test_output_override(self) -> None:
        args = parse_args(["--output", "stdout"])
        assert args.output == "stdout"

    def test_count_override(self) -> None:
        args = parse_args(["--count", "500"])
        assert args.count == 500

    def test_log_level(self) -> None:
        args = parse_args(["--log-level", "DEBUG"])
        assert args.log_level == "DEBUG"


class TestMain:
    """Tests for the main() function."""

    def test_main_returns_zero(self) -> None:
        result = main(["--log-level", "WARNING"])
        assert result == 0
