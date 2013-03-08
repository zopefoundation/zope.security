##############################################################################
#
# Copyright (c) 2004-2011 Zope Foundation and Contributors.
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
"""Testing support code

This module provides some helper/stub objects for setting up interactions.
"""
import sys
import re

from zope import interface, component
from zope.security import interfaces
from zope.security.permission import Permission
import contextlib
import zope.security.management
from zope.testing import renormalizing

PY2 = sys.version_info[0] == 2

if PY2:
    _u = unicode
    rules = [(re.compile("b('.*?')"), r"\1"),
             (re.compile('b(".*?")'), r"\1"),
            ]
    output_checker = renormalizing.RENormalizing(rules)
else:
    _u = str
    rules = [(re.compile("u('.*?')"), r"\1"),
             (re.compile('u(".*?")'), r"\1"),
            ]
    output_checker = renormalizing.RENormalizing(rules)

@interface.implementer(interfaces.IPrincipal)
class Principal:

    def __init__(self, id, title=None, description='', groups=None):
        self.id = id
        self.title = title or id
        self.description = description
        if groups is not None:
            self.groups = groups
            interface.directlyProvides(self, interfaces.IGroupAwarePrincipal)


@interface.implementer(interfaces.IParticipation)
class Participation:

    def __init__(self, principal):
        self.principal = principal
        self.interaction = None


def addCheckerPublic():
    """Add the CheckerPublic permission as 'zope.Public'"""

    perm = Permission('zope.Public', 'Public',
            """Special permission used for resources that are always public

            The public permission is effectively an optimization, sine
            it allows security computation to be bypassed.
            """
            )
    gsm = component.getGlobalSiteManager()
    gsm.registerUtility(perm, interfaces.IPermission, perm.id)


def create_interaction(principal_id, **kw):
    principal = Principal(principal_id, **kw)
    participation = Participation(principal)
    zope.security.management.newInteraction(participation)
    return principal


@contextlib.contextmanager
def interaction(principal_id, **kw):
    if zope.security.management.queryInteraction():
        # There already is an interaction. Great. Leave it alone.
        yield
    else:
        principal = create_interaction(principal_id, **kw)
        try:
            yield principal
        finally:
            zope.security.management.endInteraction()
