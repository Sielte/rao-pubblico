import logging
import subprocess

from rao import settings


class MyFilter(logging.Filter):
    def filter(self, record):
        record.version = settings.APP_VERSION
        return True
