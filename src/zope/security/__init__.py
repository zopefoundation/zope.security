##############################################################################
#
# Copyright (c) 2004 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Base security system

"""
# We need the injection of DecoratedSecurityCheckerDescriptor into
# zope.location's LocationProxy as soon someone uses security proxies by
# importing zope.security.proxy:
import zope.security.decorator
from zope.security.checker import canAccess
from zope.security.checker import canWrite
from zope.security.management import checkPermission
