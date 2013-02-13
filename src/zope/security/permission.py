##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
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
"""Permissions
"""
__docformat__ = "reStructuredText"

import operator

from zope.component import getUtilitiesFor
from zope.component import queryUtility
from zope.interface import directlyProvides
from zope.interface import implementer
from zope.schema.interfaces import IVocabularyFactory
from zope.schema.vocabulary import SimpleTerm
from zope.schema.vocabulary import SimpleVocabulary

from zope.security.checker import CheckerPublic
from zope.security.interfaces import IPermission
from zope.security._compat import _u

@implementer(IPermission)
class Permission(object):

    def __init__(self, id, title="", description=""):
        self.id = id
        self.title = title
        self.description = description

def checkPermission(context, permission_id):
    """Check whether a given permission exists in the provided context.
    """
    if permission_id is CheckerPublic:
        return
    if not queryUtility(IPermission, permission_id, context=context):
        raise ValueError("Undefined permission id", permission_id)

def allPermissions(context=None):
    """Get the ids of all defined permissions
    """
    for id, permission in getUtilitiesFor(IPermission, context):
        if id != _u('zope.Public'):
            yield id

def PermissionsVocabulary(context=None):
    """A vocabulary of permission IDs.

    Term values are permissions, while term tokens are permission IDs.
    """
    terms = []
    for id, permission in getUtilitiesFor(IPermission, context):
        terms.append(SimpleTerm(permission, id))
    return SimpleVocabulary(terms)

directlyProvides(PermissionsVocabulary, IVocabularyFactory)

def PermissionIdsVocabulary(context=None):
    """A vocabulary of permission IDs.

    Term values are the permission ID strings except for 'zope.Public', which
    is the global permission CheckerPublic.

    Term titles are the permission ID strings except for 'zope.Public', which
    is shortened to 'Public'.

    Terms are sorted by title except for 'Public', which always appears as
    the first term.
    """
    terms = []
    has_public = False
    for name, permission in getUtilitiesFor(IPermission, context):
        if name == 'zope.Public':
            has_public = True
        else:
            terms.append(SimpleTerm(name, name, name))
    terms = sorted(terms, key=operator.attrgetter('title'))
    if has_public:
        terms.insert(0, SimpleTerm(CheckerPublic, 'zope.Public', _u('Public')))
    return SimpleVocabulary(terms)

directlyProvides(PermissionIdsVocabulary, IVocabularyFactory)
