import logging
import subprocess

from rao import settings


class SystemLogFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, 'client_ip'):
            record.client_ip = 'N.D.'
        record.version = settings.APP_VERSION
        record.rao_name = settings.RAO_NAME
        return True

