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
from zope.security.interfaces import PUBLIC_PERMISSION_NAME as zope_Public
from zope.security.interfaces import IPermission


@implementer(IPermission)
class Permission(object):
    """
    Default implementation of :class:`zope.security.interfaces.IPermission`.
    """

    def __init__(self, id, title=u"", description=u""):
        self.id = id
        self.title = title
        self.description = description


def checkPermission(context, permission_id):
    """
    Check whether a given permission object exists in the provided
    context as a utility.
    """
    if permission_id is CheckerPublic:
        return
    if not queryUtility(IPermission, permission_id, context=context):
        raise ValueError("Undefined permission ID", permission_id)


def allPermissions(context=None):
    """
    Get the IDs of all defined permission object utilities.
    """
    for name, _permission in getUtilitiesFor(IPermission, context):
        if name != zope_Public:
            yield name


def PermissionsVocabulary(context=None):
    """
    A vocabulary of permission IDs.

    Term values are permissions, while term tokens are permission IDs.
    """
    terms = []
    for name, permission in getUtilitiesFor(IPermission, context):
        terms.append(SimpleTerm(permission, name))
    return SimpleVocabulary(terms)


directlyProvides(PermissionsVocabulary, IVocabularyFactory)


def PermissionIdsVocabulary(context=None):
    """
    A vocabulary of permission IDs.

    Term values are the permission ID strings except for
    :data:`zope.Public
    <zope.security.interfaces.PUBLIC_PERMISSION_NAME>`, which is the
    global permission :data:`zope.security.checker.CheckerPublic`.

    Term titles are the permission ID strings except for
    :data:`zope.Public
    <zope.security.interfaces.PUBLIC_PERMISSION_NAME>`, which is
    shortened to 'Public'.

    Terms are sorted by title except for 'Public', which always appears as
    the first term.
    """
    terms = []
    has_public = False
    for name, _permission in getUtilitiesFor(IPermission, context):
        if name == zope_Public:
            has_public = True
        else:
            terms.append(SimpleTerm(name, name, name))
    terms = sorted(terms, key=operator.attrgetter('title'))
    if has_public:
        terms.insert(0, SimpleTerm(CheckerPublic, zope_Public, u'Public'))
    return SimpleVocabulary(terms)


directlyProvides(PermissionIdsVocabulary, IVocabularyFactory)
