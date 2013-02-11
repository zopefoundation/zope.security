##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
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
"""Default 'ISecurityManagement' and 'IInteractionManagement' implementation
"""

from zope.interface import moduleProvides

from zope.security.checker import CheckerPublic
from zope.security.interfaces import IInteractionManagement
from zope.security.interfaces import ISecurityManagement
from zope.security.interfaces import NoInteraction
from zope.security.simplepolicies import ParanoidSecurityPolicy
from zope.security._definitions import thread_local
from zope.security._definitions import system_user # API?


_defaultPolicy = ParanoidSecurityPolicy

moduleProvides(
    ISecurityManagement,
    IInteractionManagement)

#
#   ISecurityManagement implementation
#

def getSecurityPolicy():
    """Get the system default security policy."""
    return _defaultPolicy

def setSecurityPolicy(aSecurityPolicy):
    """Set the system default security policy, and return the previous
    value.

    This method should only be called by system startup code.
    It should never, for example, be called during a web request.
    """
    global _defaultPolicy

    last, _defaultPolicy = _defaultPolicy, aSecurityPolicy

    return last


#
#   IInteractionManagement implementation
#

def queryInteraction():
    return getattr(thread_local, 'interaction', None)

def getInteraction():
    """Get the current interaction."""
    try:
        return thread_local.interaction
    except AttributeError:
        raise NoInteraction

class ExistingInteraction(ValueError,
                          AssertionError, #BBB
                         ):
    pass

def newInteraction(*participations):
    """Start a new interaction."""
    if queryInteraction() is not None:
        raise ExistingInteraction("newInteraction called"
                             " while another interaction is active.")
    thread_local.interaction = getSecurityPolicy()(*participations)

def endInteraction():
    """End the current interaction."""

    try:
        thread_local.previous_interaction = thread_local.interaction
    except AttributeError:
        # if someone does a restore later, it should be restored to not having
        # an interaction.  If there was a previous interaction from a previous
        # call to endInteraction, it should be removed.
        try:
            del thread_local.previous_interaction
        except AttributeError:
            pass
    else:
        del thread_local.interaction

def restoreInteraction():
    try:
        previous = thread_local.previous_interaction
    except AttributeError:
        try:
            del thread_local.interaction
        except AttributeError:
            pass
    else:
        thread_local.interaction = previous

def checkPermission(permission, object, interaction=None):
    """Return whether security policy allows permission on object.

    'permission' is a permission name.

    'object' is the object being accessed according to the permission.

    'interaction' is an interaction, providing access to information
    such as authenticated principals.  If it is None, the current
    interaction is used.

    checkPermission is guaranteed to return True if permission is
    CheckerPublic or None.
    """
    if permission is CheckerPublic or permission is None:
        return True
    if interaction is None:
        try:
            interaction = thread_local.interaction
        except AttributeError:
            raise NoInteraction
    return interaction.checkPermission(permission, object)


def _clear():
    global _defaultPolicy
    _defaultPolicy = ParanoidSecurityPolicy

# XXX This code is used to support automated testing. However, it shouldn't be
# here and needs to be refactored. The empty addCleanUp-method is a temporary
# workaround to fix packages that depend on zope.security but don't have a
# need for zope.testing.
try:
    from zope.testing.cleanup import addCleanUp
except ImportError: #pragma NO COVER
    pass
else:
    addCleanUp(_clear)
    addCleanUp(endInteraction)
