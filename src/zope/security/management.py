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
"""
Default :class:`zope.security.interfaces.ISecurityManagement` and
:class:`zope.security.interfaces.IInteractionManagement` implementation.

Note that this module itself provides those interfaces.
"""

from zope.interface import moduleProvides

from zope.security._definitions import system_user
from zope.security._definitions import thread_local
from zope.security.checker import CheckerPublic
from zope.security.interfaces import IInteractionManagement
from zope.security.interfaces import ISecurityManagement
from zope.security.interfaces import NoInteraction
from zope.security.simplepolicies import ParanoidSecurityPolicy


__all__ = [
    'system_user',
    'getSecurityPolicy',
    'setSecurityPolicy',
    'queryInteraction',
    'getInteraction',
    'ExistingInteraction',
    'newInteraction',
    'endInteraction',
    'restoreInteraction',
    'checkPermission',
]

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
    """Return a current interaction, if there is one."""
    return getattr(thread_local, 'interaction', None)


def getInteraction():
    """Get the current interaction."""
    try:
        return thread_local.interaction
    except AttributeError:
        raise NoInteraction


class ExistingInteraction(ValueError,
                          AssertionError,  # BBB
                          ):
    """
    The exception that :func:`newInteraction` will raise if called
    during an existing interaction.
    """


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

    :param str permission: A permission name.
    :param object: The object being accessed according to the permission.
    :param interaction: An interaction, providing access to information
        such as authenticated principals.  If it is None, the current
        interaction is used.
    :return: A boolean value. ``checkPermission`` is guaranteed to
        return ``True`` if *permission* is
        :data:`zope.security.checker.CheckerPublic` or ``None``.
    :raise NoInteraction: If there is no current interaction and no
        interaction argument was given.
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


try:
    from zope.testing.cleanup import addCleanUp
except ImportError:  # pragma: no cover
    pass
else:
    addCleanUp(_clear)
    addCleanUp(endInteraction)
