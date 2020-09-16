import subprocess

from rao import settings


def version_context_processor(request):
    my_dict = {
        'version_app': settings.APP_VERSION,
    }
    return my_dict
