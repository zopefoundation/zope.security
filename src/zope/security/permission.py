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

from zope.interface import implementer, directlyProvides
from zope.component import queryUtility, getUtilitiesFor
from zope.schema.interfaces import IVocabularyFactory
from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm
from zope.security.checker import CheckerPublic
from zope.security.interfaces import IPermission

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
        if id != u'zope.Public':
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
    for name, permission in getUtilitiesFor(IPermission, context):
        if name == 'zope.Public':
            terms.append(SimpleTerm(CheckerPublic, 'zope.Public', u'Public'))
        else:
            terms.append(SimpleTerm(name, name, name))
    terms.sort(cmp=lambda lhs, rhs: \
               (lhs.token == 'zope.Public' and -1) or cmp(lhs.title, rhs.title))
    return SimpleVocabulary(terms)

directlyProvides(PermissionIdsVocabulary, IVocabularyFactory)
