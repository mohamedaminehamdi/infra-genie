"""
Logging Configuration Module
============================

Provides centralized logging configuration for Infra-Genie.

This module sets up structured logging with:
- Console output with rich formatting
- Optional file logging
- Configurable log levels
- Request ID tracking for debugging

Functions
---------
setup_logging
    Configure application-wide logging.
get_logger
    Get a logger for a specific module.

Example
-------
>>> from src.core.logging import setup_logging, get_logger
>>>
>>> # Setup logging at application start
>>> setup_logging(level="INFO", log_file="infra-genie.log")
>>>
>>> # Get logger in modules
>>> logger = get_logger(__name__)
>>> logger.info("Starting scan")

Log Levels
----------
- DEBUG: Detailed diagnostic information
- INFO: General operational messages
- WARNING: Potential issues that don't prevent operation
- ERROR: Errors that prevent specific operations
- CRITICAL: Fatal errors requiring immediate attention

See Also
--------
logging : Python standard library logging module.
rich.logging : Rich library's logging handler.
"""

from __future__ import annotations

import logging
from typing import Optional, Union

from rich.console import Console
from rich.logging import RichHandler

# Default format for log messages
DEFAULT_FORMAT = "%(message)s"
FILE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    level: Union[str, int] = "INFO",
    log_file: Optional[str] = None,
    rich_tracebacks: bool = True,
    console: Optional[Console] = None,
) -> None:
    """
    Configure application-wide logging.

    Sets up logging with Rich console handler and optional file handler.
    Should be called once at application startup.

    Parameters
    ----------
    level : str or int, default="INFO"
        Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    log_file : str, optional
        Path to log file. If provided, logs will be written to this file.
    rich_tracebacks : bool, default=True
        Whether to use Rich for exception tracebacks.
    console : Console, optional
        Rich Console instance. If not provided, creates a new one.

    Examples
    --------
    Basic setup:

    >>> setup_logging(level="INFO")

    With file logging:

    >>> setup_logging(level="DEBUG", log_file="infra-genie.log")

    Quiet mode (errors only):

    >>> setup_logging(level="ERROR")

    Notes
    -----
    This function configures the root logger and should only be called
    once at application startup. Subsequent calls will add additional
    handlers.
    """
    # Convert string level to int if needed
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Create Rich console handler
    rich_console = console or Console(stderr=True)
    console_handler = RichHandler(
        console=rich_console,
        show_time=True,
        show_path=False,
        rich_tracebacks=rich_tracebacks,
        tracebacks_show_locals=False,
        markup=True,
    )
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
    root_logger.addHandler(console_handler)

    # Add file handler if requested
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(
            logging.Formatter(FILE_FORMAT, datefmt=DATE_FORMAT)
        )
        root_logger.addHandler(file_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    root_logger.debug(
        f"Logging configured: level={logging.getLevelName(level)}, "
        f"file={log_file or 'None'}"
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Parameters
    ----------
    name : str
        Logger name (typically __name__ from the calling module).

    Returns
    -------
    logging.Logger
        Configured logger instance.

    Example
    -------
    >>> logger = get_logger(__name__)
    >>> logger.info("Starting operation")
    >>> logger.debug("Debug details: %s", details)
    """
    return logging.getLogger(name)


class LogContext:
    """
    Context manager for temporary log level changes.

    Useful for temporarily increasing verbosity for specific operations.

    Parameters
    ----------
    logger : logging.Logger
        Logger to modify.
    level : str or int
        Temporary log level.

    Example
    -------
    >>> logger = get_logger(__name__)
    >>> with LogContext(logger, "DEBUG"):
    ...     logger.debug("This will be shown")
    >>> logger.debug("This won't be shown at INFO level")
    """

    def __init__(
        self,
        logger: logging.Logger,
        level: Union[str, int],
    ) -> None:
        """Initialize log context."""
        self.logger = logger
        self.new_level = (
            getattr(logging, level.upper()) if isinstance(level, str) else level
        )
        self.original_level: Optional[int] = None

    def __enter__(self) -> logging.Logger:
        """Enter context and set new log level."""
        self.original_level = self.logger.level
        self.logger.setLevel(self.new_level)
        return self.logger

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context and restore original log level."""
        if self.original_level is not None:
            self.logger.setLevel(self.original_level)
