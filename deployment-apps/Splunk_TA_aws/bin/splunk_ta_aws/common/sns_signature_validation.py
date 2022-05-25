#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
loads crypto lib and validates sns signatures
"""
import os
import sys
from ctypes.util import find_library  # pylint: disable=W0611 # noqa: F401
from urllib.request import urlopen

from oscrypto import _module_values, use_ctypes, use_openssl
from splunksdc import log as logging

logger = logging.get_module_logger()

# has 3 states
# None : has not tried to load libvrypto
# False: failed to load libcrypto
# a function: loaded libcrypto and can use this function
validate_aws_sns_message_validate = None  # pylint: disable=C0103


def load_libcrypto():
    """
    Finds and loads libcrypto
    If fails it will set validate_aws_sns_message_validate to false
    if success validate_aws_sns_message_validate will be the validation function
    """

    global validate_aws_sns_message_validate  # pylint: disable=C0103,W0603

    if validate_aws_sns_message_validate is None:  # pylint: disable=R1702
        validate_aws_sns_message_validate = False
        try:
            logger.debug("search for libcrypto")
            # forces crypoto to use ctypes
            _module_values["ffi"] == "ctypes"  # pylint: disable=W0104
            # find the libcrypto.so for linux / darwin. Win use os native libraries

            if os.name == "posix":
                # if set to "dylib" this code can work on darmin
                libcrypto = False
                libssl = False
                ext = "so"
                if sys.platform == "darwin":
                    ext = "dylib"

                # try to load splunk libcrrypto will check in lib paths
                # as last resort we will assume that the lib path is $SPLUNK_HOME/lib

                for env_name in ["DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH", "SPLUNK_HOME"]:
                    if env_name in os.environ:
                        lib_path = os.environ[env_name]  # pylint: disable=C0103
                        logger.debug(f"libcrypto looking in {lib_path}")
                        if os.path.exists(os.path.join(lib_path, "libcrypto." + ext)):
                            libcrypto = os.path.join(lib_path, "libcrypto." + ext)
                            libssl = os.path.join(lib_path, "libssl." + ext)
                            logger.debug(
                                f"libcrypto found in {lib_path} : {libcrypto}, {libssl}"
                            )
                            break

                if libcrypto:
                    use_openssl(libcrypto, libssl)

        except Exception as ex:  # pylint: disable=W0703
            logger.error(f"can not find libcrypto {ex}")

        try:
            # backend needs to be reset or will throw an error when setting ctypes
            _module_values["backend"] = None
            # use_ctypes needs to be called again because use_openssl resets it
            use_ctypes()
            import validate_aws_sns_message  # pylint: disable=C0415

            validate_aws_sns_message_validate = validate_aws_sns_message
            logger.info("Loaded libcrypto")
        except Exception as ex:  # pylint:  disable=W0703
            logger.warning(
                f"Could not load libCrypto running with no signature validation: {ex}"
            )
            validate_aws_sns_message_validate = False


cache_certificates = {}


def set_certificate_cache(url, certificate):
    """
    Adds certificate to cache_certificates
    """
    cache_certificates[url] = certificate


def get_certificate(url):
    """
    receives a URL to a certificate, caches in memory, and returns a certificate
    """
    if url not in cache_certificates:
        set_certificate_cache(url, urlopen(url).read())  # pylint: disable=R1732
        logger.debug(f"Fetched SNS Certificate: {url}")

    return cache_certificates[url]


def sqs_validate(message):
    """
    For validating sns/sqs message signatures.

    message (dict) : dictionary of message

    throws exception on invalid signature
    """
    load_libcrypto()
    # Raise validate_aws_sns_message.ValidationError if message is invalid.
    if validate_aws_sns_message_validate:
        logger.debug("validating", message)
        validate_aws_sns_message_validate.validate(
            message
        )  # , get_certificate=get_certificate)
    else:
        logger.warning(
            f"crypto is not loading ignoring SNS validation: {message.message_id}"
        )
