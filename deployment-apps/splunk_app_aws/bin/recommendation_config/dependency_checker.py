__author__ = 'frank'

import platform
import re
from app_aws_bin.utils.local_manager import LocalServiceManager
import app_aws_bin.utils.app_util as utils

logger = utils.get_logger()

COMPATIBLE_SA_VERSIONS = ['1.1', '1.2']
AWS_SA_SUFFIX = '_awsapp'


def is_ml_lib_included(session_key):

    supported_systems = {
        ('Linux', 'i386'): 'linux_x86',
        ('Linux', 'x86_64'): 'linux_x86_64',
        ('Darwin', 'x86_64'): 'darwin_x86_64',
        ('Windows', 'AMD64'): 'windows_x86_64'
    }

    system = (platform.system(), platform.machine())

    sa_name = 'Splunk_SA_Scientific_Python_%s' % (supported_systems[system])

    try:
        sa_ver = utils.get_option_from_conf(
            session_key, "app", "launcher", "version", sa_name)
        logger.info("Found " + sa_name + " version " + str(sa_ver))
    except:
        sa_ver = None
        logger.info("Unable to locate " + sa_name)

    aws_sa_name = sa_name + AWS_SA_SUFFIX

    try:
        aws_sa_ver = utils.get_option_from_conf(
            session_key, "app", "launcher", "version", aws_sa_name)
        logger.info("Found " + aws_sa_name + " version " + str(aws_sa_ver))
    except:
        aws_sa_ver = None
        logger.info("Unable to locate " + aws_sa_name)

    if ((sa_ver in COMPATIBLE_SA_VERSIONS) or (aws_sa_ver in COMPATIBLE_SA_VERSIONS)) and (sa_ver is not None):
        return True
    return False


def is_splunk_light(session_key):
    service = LocalServiceManager(session_key=session_key).get_local_service()
    product_type = service.info()['product_type']
    return product_type == 'lite' or product_type == 'lite_free'
