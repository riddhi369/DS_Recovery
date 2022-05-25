#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
"""
Add common libs to sys.path
"""

import logging
import os
import os.path
import re
import sys


def setup_python_path():
    """Sets up path for python modules."""
    # Exclude folder beneath other apps, Fix bug for rest_handler.py
    ta_name = os.path.basename(os.path.dirname(os.path.dirname(__file__)))
    pattern = re.compile(r"[\\/]etc[\\/]apps[\\/][^\\/]+[\\/]bin[\\/]?$")
    new_paths = [
        path for path in sys.path if not pattern.search(path) or ta_name in path
    ]
    new_paths.insert(0, os.path.dirname(__file__))
    sys.path = new_paths

    package_dir = os.path.dirname(os.path.dirname(__file__))
    # We sort the precedence in a decending order since sys.path.insert(0, ...)
    # do the reversing.
    # Insert library folder
    sharedpath = os.path.join(package_dir, "lib")
    sys.path.insert(0, sharedpath)

    # inserted commited splunktalib as first priority on path
    path_to_splunktalib = os.path.join(sharedpath, "splunktalib_helper")
    sys.path.insert(0, path_to_splunktalib)


# preventing splunklib initialize an unexpected root handler
def setup_null_handler():
    """Sets up logging handler."""
    logging.root.addHandler(logging.NullHandler())


def run_module(name):
    """Runs the main module."""
    instance = __import__(name, fromlist=["main"])
    instance.main()


setup_python_path()
setup_null_handler()
