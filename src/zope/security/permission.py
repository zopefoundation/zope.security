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

$Id$
"""
__docformat__ = "reStructuredText"

from zope.interface import implements, directlyProvides
from zope.component import queryUtility, getUtilitiesFor
from zope.schema.interfaces import IVocabularyFactory
from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm
from zope.security.checker import CheckerPublic
from zope.security.interfaces import IPermission

class Permission(object):
    implements(IPermission)

    def __init__(self, id, title="", description=""):
        self.id = id
        self.title = title
        self.description = description

def checkPermission(context, permission_id):
    """Check whether a given permission exists in the provided context.

    >>> from zope.component import provideUtility
    >>> provideUtility(Permission('x'), IPermission, 'x')

    >>> checkPermission(None, 'x')
    >>> checkPermission(None, 'y')
    Traceback (most recent call last):
    ...
    ValueError: ('Undefined permission id', 'y')
    
    The CheckerPublic always exists:
    
    >>> checkPermission(None, CheckerPublic)
    
    """
    if permission_id is CheckerPublic:
        return
    if not queryUtility(IPermission, permission_id, context=context):
        raise ValueError("Undefined permission id", permission_id)

def allPermissions(context=None):
    """Get the ids of all defined permissions

    >>> from zope.component import provideUtility
    >>> provideUtility(Permission('x'), IPermission, 'x')
    >>> provideUtility(Permission('y'), IPermission, 'y')

    >>> ids = list(allPermissions(None))
    >>> ids.sort()
    >>> ids
    [u'x', u'y']
    """
    for id, permission in getUtilitiesFor(IPermission, context):
        if id != u'zope.Public':
            yield id

def PermissionsVocabulary(context=None):
    """A vocabulary of permission IDs.

    Term values are permissions, while term tokens are permission IDs.
    
    To illustrate, we need to register the permission IDs vocabulary:

    >>> from zope.schema.vocabulary import _clear
    >>> _clear()

    >>> from zope.schema.vocabulary import getVocabularyRegistry
    >>> registry = getVocabularyRegistry()
    >>> registry.register('Permissions', PermissionsVocabulary)

    We also need to register some sample permission utilities:

    >>> from zope.security.interfaces import IPermission
    >>> from zope.security.permission import Permission
    >>> from zope.component import provideUtility
    >>> a = Permission('a')
    >>> b = Permission('b')
    >>> provideUtility(a, IPermission, 'a')
    >>> provideUtility(b, IPermission, 'b')

    We can now lookup these permissions using the vocabulary:

    >>> vocab = registry.get(None, 'Permissions')
    >>> vocab.getTermByToken('a').value is a
    True
    >>> vocab.getTermByToken('b').value is b
    True

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

    To illustrate, we need to register the permission IDs vocabulary:

    >>> from zope.schema.vocabulary import _clear
    >>> _clear()

    >>> from zope.schema.vocabulary import getVocabularyRegistry
    >>> registry = getVocabularyRegistry()
    >>> registry.register('Permission Ids', PermissionIdsVocabulary)

    We also need to register some sample permission utilities, including
    the special permission 'zope.Public':

    >>> from zope.security.interfaces import IPermission
    >>> from zope.security.permission import Permission
    >>> from zope.component import provideUtility
    >>> provideUtility(Permission('zope.Public'), IPermission, 'zope.Public')
    >>> provideUtility(Permission('b'), IPermission, 'b')
    >>> provideUtility(Permission('a'), IPermission, 'a')

    We can now lookup these permissions using the vocabulary:

    >>> vocab = registry.get(None, 'Permission Ids')

    The non-public permissions 'a' and 'b' are string values:

    >>> vocab.getTermByToken('a').value
    u'a'
    >>> vocab.getTermByToken('b').value
    u'b'

    However, the public permission value is CheckerPublic:

    >>> vocab.getTermByToken('zope.Public').value is CheckerPublic
    True

    and its title is shortened:

    >>> vocab.getTermByToken('zope.Public').title
    u'Public'

    The terms are sorted by title except for the public permission, which is
    listed first:

    >>> [term.title for term in vocab]
    [u'Public', u'a', u'b']
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
