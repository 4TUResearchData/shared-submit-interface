"""
This module provides convenience functions that can be used throughout
the codebase.
"""

import logging
from datetime import datetime

def value_or (record, key, other):
    """Return the value of KEY or OTHER."""
    try:
        return record[key]
    except (IndexError, KeyError, TypeError):
        return other

def value_or_none (record, key):
    """Return the value of KEY or None."""
    return value_or (record, key, None)

def index_exists (value, index):
    """Procedure to test whether a list or string has a certain length."""
    try:
        value[index]
    except IndexError:
        return False

    return True

def epoch_to_human_readable (epoch):
    """Returns a human-readable string for EPOCH."""
    return datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%dT%H:%M:%SZ')

def add_logging_level (level_name, level_number, method_name=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `level_name` becomes an attribute of the `logging` module with the value
    `level_number`. `method_name` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `method_name` is not specified, `level_name.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    not overwrite existing attributes.

    Code copied and adapted from the following Stack Overflow post:
    https://stackoverflow.com/questions/2183233/35804945#35804945
    """
    if not method_name:
        method_name = level_name.lower()

    if (hasattr(logging, level_name) or
        hasattr(logging, method_name) or
        hasattr(logging.getLoggerClass(), method_name)):
        return

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def log_for_level(self, message, *args, **kwargs):
        if self.isEnabledFor(level_number):
            self._log(level_number, message, args, **kwargs) # pylint: disable=protected-access

    def log_to_root(message, *args, **kwargs):
        logging.log(level_number, message, *args, **kwargs)

    logging.addLevelName(level_number, level_name)
    setattr(logging, level_name, level_number)
    setattr(logging.getLoggerClass(), method_name, log_for_level)
    setattr(logging, method_name, log_to_root)
