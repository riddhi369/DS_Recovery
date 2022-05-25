#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2011-2016 Splunk, Inc.


from __future__ import absolute_import, division, print_function, unicode_literals
from splunklib.searchcommands import Option,validators
import splunk.Intersplunk
import sys
from ua_parser.user_agent_parser import (UserAgentParser, OSParser)
from ua_parser._regexes import (USER_AGENT_PARSERS, OS_PARSERS, DEVICE_PARSERS)
import app_aws_bin.utils.app_util as util
logger = util.get_logger()


def _load_custom_rules():
    """
    Load custom rules and preprend them to have precedence over ua-parser library's rules.
    There is 3 different types of rules:
     - Device
     - OS
     - UA

    A device rule regexp is composed by 3 groups which fill respectively: device, brand, model
    An OS rule regexp is composed by 5 groups which fill respectively: os_family, os_major, os_minor, os_patch, os_patch_minor
    An UA rule regexp is composed by 4 groups which fill respectively: ua_family, ua_major, ua_minor, ua_patch

    For each type of rule, a regexp group can be replaced. This replacement is defined in the parser's constructor.

    For more details, please refer to ua-parser documentation https://github.com/ua-parser/uap-python

    """
    USER_AGENT_PARSERS.insert(0, UserAgentParser('(AppleCoreMedia)(?:/(\d+)\.(\d+)\.?\d+.*Apple\s?TV?)?',
                                                 'Apple TV native player'))
    OS_PARSERS.insert(0, OSParser('(Apple\s?TV)(?:/(\d+)\.(\d+))?', 'Apple TV OS X'))
    OS_PARSERS.append(OSParser('(iPhone|iPad|iPod).*[iI]OS (\d+)\.(\d+)', 'iOS'))


    """ Give details about OS, browser, device based on a given user agent string.
    ##Syntax
    .. code-block::
        useragent (prefix=string)? (device=bool)? (os=bool)? (ua=bool)? user-agent-fieldname
    ##Description
    The user agent field in user-agent-fieldname is parsed to extract device, OS, user agent information.
    According to options selected, respective fields will be added:
     - ua option enabled: ua_family, ua_major, ua_minor, ua_patch
     - os option enabled: os_family, os_major, os_minor, os_patch, os_patch_minor
     - device option enabled: device, brand, model
    By default, all fields are added.
    Not all of the information is available for all user agents, and hence it is normal to have some of the fields empty.
    prefix=string will add a certain prefix to all fieldnames if you desire to uniquely qualify added field names and avoid name collisions with existing fields (default is null/empty string).
    ##Example
    This example extracts only user agent's information from field ua_from_js. It will also prefix added fields with my_ua_.
    .. code-block::
        ... | useragent prefix=my_ua_ device=f os=f ua_from_js
    """
prefix = Option(
        doc='''
    **Syntax:** **prefix=***<prefix>*
    **Description:** Prefix value used to prevent name collision with others fields.''',
        require=False, validate=validators.Fieldname(), default=None)
os = Option(
        doc='''
    **Syntax:** **os=***<bool>*
    **Description:** Enable os information extraction: os_family, os_major, os_minor, os_patch, os_patch_minot fields will be added.''',
        require=False, validate=validators.Boolean(), default=True)
ua = Option(
        doc='''
    **Syntax:** **ua=***<bool>*
    **Description:** Enable user agent information extraction: ua_family, ua_major, ua_minor, ua_patch fields will be added.''',
        require=False, validate=validators.Boolean(), default=True)
device = Option(
        doc='''
    **Syntax:** **device=***<bool>*
    **Description:** Enable device information extraction: device, brand, model fields will be added.''',
        require=False, validate=validators.Boolean(), default=True)

def _find_os_info(user_agent):
    os = os_v1 = os_v2 = os_v3 = os_v4 = None
    try:
        for parser in OS_PARSERS:
            os, os_v1, os_v2, os_v3, os_v4 = parser.Parse(user_agent)
            if os:
                break
    except Exception:
        logger.exception('An exception occured during parsing user agent to extract os info')
    return os, os_v1, os_v2, os_v3, os_v4


def _find_ua_info(user_agent):
    family = v1 = v2 = v3 = None
    try:
        for parser in USER_AGENT_PARSERS:
            family, v1, v2, v3 = parser.Parse(user_agent)
            if family:
                break
    except Exception:
        logger.exception('An exception occured during parsing user agent to extract ua info')
    return family, v1, v2, v3


def _find_device_info(user_agent):
    device, brand, model = None, None, None
    try:
        for parser in DEVICE_PARSERS:
            device, brand, model = parser.Parse(user_agent)
            if device:
                break
    except Exception:
        logger.exception('An exception occured during parsing user agent to extract device info')
    return device, brand, model

_load_custom_rules()

# Default all feild display as per previous command
os=True
ua=True
device=True

records = splunk.Intersplunk.readResults(None, None, True)
if ua or os or device:
    prefix = ''
    for arg in sys.argv:
        if("prefix" in arg):
            if(len(arg.split('=')) > 1):
                prefix = arg.split('=')[1]
        elif("os=f" in arg):
            os = False
        elif("device=f" in arg):
            device = False
        elif("ua=f" in arg):
            ua = False
    
    for record in records:
        user_agent = record.get("http_user_agent")
        if user_agent:
            if os:
                os, os_v1, os_v2, os_v3, os_v4 = _find_os_info(user_agent)
                record[prefix + 'os_family'] = os
                record[prefix + 'os_major'] = os_v1
                record[prefix + 'os_minor'] = os_v2
                record[prefix + 'os_patch'] = os_v3
                record[prefix + 'os_patch_minor'] = os_v4
            if ua:
                family, v1, v2, v3 = _find_ua_info(user_agent)
                record[prefix + 'ua_family'] = family
                record[prefix + 'ua_major'] = v1
                record[prefix + 'ua_minor'] = v2
                record[prefix + 'ua_patch'] = v3
            if device:
                device, brand, model = _find_device_info(user_agent)
                record[prefix + 'device'] = device
                record[prefix + 'brand'] = brand
                record[prefix + 'model'] = model


splunk.Intersplunk.outputResults(records)

