import logging
from logging.handlers import RotatingFileHandler
from .colors import *

__all__ = ['setup_logger', 'console_log_level', 'file_log_level', 'log_file']

# Default log levels and log file path
console_log_level = 'INFO'
file_log_level = None
log_file = 'xsstrike.log'

"""
Custom Logging Levels:
CRITICAL = 50
ERROR = 40
WARNING = 30
INFO = 20
DEBUG = 10
"""

VULN_LEVEL_NUM = 60
RUN_LEVEL_NUM = 22
GOOD_LEVEL_NUM = 25

# Adding custom levels to the logging module
logging.addLevelName(VULN_LEVEL_NUM, 'VULN')
logging.addLevelName(RUN_LEVEL_NUM, 'RUN')
logging.addLevelName(GOOD_LEVEL_NUM, 'GOOD')


def _vuln(self, msg, *args, **kwargs):
    """Custom log level for vulnerabilities."""
    if self.isEnabledFor(VULN_LEVEL_NUM):
        self._log(VULN_LEVEL_NUM, msg, args, **kwargs)


def _run(self, msg, *args, **kwargs):
    """Custom log level for runtime information."""
    if self.isEnabledFor(RUN_LEVEL_NUM):
        self._log(RUN_LEVEL_NUM, msg, args, **kwargs)


def _good(self, msg, *args, **kwargs):
    """Custom log level for positive results."""
    if self.isEnabledFor(GOOD_LEVEL_NUM):
        self._log(GOOD_LEVEL_NUM, msg, args, **kwargs)


# Extend the logger to include custom levels
logging.Logger.vuln = _vuln
logging.Logger.run = _run
logging.Logger.good = _good

# Log configuration for different log levels with color-coded prefixes
log_config = {
    'DEBUG': {
        'value': logging.DEBUG,
        'prefix': '{}[*]{}'.format(yellow, end),
    },
    'INFO': {
        'value': logging.INFO,
        'prefix': info,
    },
    'RUN': {
        'value': RUN_LEVEL_NUM,
        'prefix': run,
    },
    'GOOD': {
        'value': GOOD_LEVEL_NUM,
        'prefix': good,
    },
    'WARNING': {
        'value': logging.WARNING,
        'prefix': '[!!]'.format(yellow, end),
    },
    'ERROR': {
        'value': logging.ERROR,
        'prefix': bad,
    },
    'VULN': {
        'value': VULN_LEVEL_NUM,
        'prefix': bad,
    },
    'CRITICAL': {
        'value': logging.CRITICAL,
        'prefix': '{}[!!]{}'.format(red, end),
    }
}


def setup_logger(name):
    """
    Sets up a logger with console and optional file handlers.
    
    Args:
        name (str): The name of the logger (typically __name__).
    
    Returns:
        logging.Logger: Configured logger object.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Capture all levels (filter applied later)

    # Console handler for logging to the terminal
    ch = logging.StreamHandler()
    ch.setLevel(log_config[console_log_level]['value'])

    # Log rotation for file handler
    if log_file:
        fh = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)  # 5MB max per file, up to 5 backups
        fh.setLevel(log_config[file_log_level]['value'] if file_log_level else log_config['DEBUG']['value'])

        # Formatter for file logging
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Custom formatter for console logging
    class CustomFormatter(logging.Formatter):
        def format(self, record):
            log_entry = log_config[record.levelname]['prefix'] + ' ' + super().format(record)
            return log_entry

    ch.setFormatter(CustomFormatter('%(message)s'))
    logger.addHandler(ch)

    return logger
