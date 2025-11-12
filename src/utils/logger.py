"""Logging utilities for dnsstego."""
from __future__ import annotations

import logging
from logging import Logger
from typing import Optional

_DEFAULT_FORMAT = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"


def get_logger(name: Optional[str] = None, level: int = logging.INFO) -> Logger:
    """Return a configured :class:`logging.Logger` instance.

    Parameters
    ----------
    name:
        Name of the logger. ``None`` returns the root logger.
    level:
        Logging level. Defaults to :data:`logging.INFO`.
    """

    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(_DEFAULT_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


__all__ = ["get_logger"]
