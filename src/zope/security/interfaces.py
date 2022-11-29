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
"""
Interfaces for security machinery.

These can be categorized into a few different groups of related objects.

* Exceptions

  - :class:`IUnauthorized`
  - :class:`IForbidden`
  - :class:`IForbiddenAttribute`
  - :class:`NoInteraction`

* Utilities

  - :class:`ISecurityManagement`
  - :class:`ISecurityChecking`
  - :class:`ISecurityProxyFactory`
  - :class:`IChecker`
  - :class:`INameBasedChecker`
  - :class:`ISecurityPolicy`

* Principals

  - :class:`IInteraction`
  - :class:`IParticipation`
  - :class:`IInteractionManagement`
  - :class:`IPrincipal`
  - :class:`ISystemPrincipal`
  - :class:`IGroupAwarePrincipal`
  - :class:`IGroupClosureAwarePrincipal`
  - :class:`IGroup`
  - :class:`IMemberGetterGroup`
  - :class:`IMemberAwareGroup`
  - :class:`IPermission`

Anywhere that an API is documented as accepting a permission, it
means the name of the permission, or the special object
:class:`zope.security.checker.CheckerPublic`.
"""

from zope.interface import Attribute
from zope.interface import Interface
from zope.interface import implementer
from zope.interface.common.interfaces import IAttributeError
from zope.interface.common.interfaces import IException
from zope.schema import NativeStringLine
from zope.schema import Text
from zope.schema import TextLine

from zope.security.i18n import ZopeMessageFactory as _


#: The name (id) of the registered :class:`IPermission` utility that signifies
#: that the protected attribute is public.
#:
#: .. versionadded:: 4.2.0
PUBLIC_PERMISSION_NAME = 'zope.Public'


class IUnauthorized(IException):
    """
    The action is not authorized.

    Implemented in :class:`Unauthorized`.
    """


@implementer(IUnauthorized)
class Unauthorized(Exception):
    """
    Some user wasn't allowed to access a resource.

    Default implementation of :class:`IUnauthorized`.
    """


class IForbidden(IException):
    """
    A resource cannot be accessed under any circumstances

    Implemented in :class:`Forbidden`.
    """


@implementer(IForbidden)
class Forbidden(Exception):
    """
    A resource cannot be accessed under any circumstances

    Default implementation if :class:`IForbidden`.
    """


class IForbiddenAttribute(IForbidden, IAttributeError):
    """
    An attribute is unavailable because it is forbidden (private).

    Implemented in :class:`ForbiddenAttribute`.
    """


@implementer(IForbiddenAttribute)
class ForbiddenAttribute(Forbidden, AttributeError):
    """
    An attribute is unavailable because it is forbidden (private).

    Default implementation of :class:`IForbiddenAttribute`.
    """


class ISecurityManagement(Interface):
    """
    Public security management API.

    This is implemented by :mod:`zope.security.management`.
    """

    def getSecurityPolicy():
        """Get the system default security policy."""

    def setSecurityPolicy(aSecurityPolicy):
        """Set the system default security policy.

        This method should only be called by system startup code.  It
        should never, for example, be called during a web request.
        """


class ISecurityChecking(Interface):
    """
    Public security API.
    """

    def checkPermission(permission, object, interaction=None):
        """
        Return whether security policy allows permission on object.

        :param str permission: The permission name.
        :param object: The object being accessed according to the permission.
        :keyword interaction: An :class:`IInteraction`, providing access to
            information such as authenticated principals.  If it is None, the
            current interaction is used.
        """


class ISecurityProxyFactory(Interface):
    """
    A factory for creating security-proxied objects.

    See :class:`zope.security.checker.ProxyFactory` for the
    default implementation.
    """

    def __call__(object, checker=None):
        """
        Create a security proxy

        If a checker (:class:`IChecker`) is given, then use it,
        otherwise, try to figure out a checker.

        If the object is already a security proxy, then it will be
        returned.
        """


class IChecker(Interface):
    """
    Security-proxy plugin objects that implement low-level checks.

    The checker is responsible for creating proxies for
    operation return values, via the ``proxy`` method.

    There are :meth:`check_getattr` and :meth:`check_setattr` methods
    for checking getattr and setattr, and a :meth:`check` method for all
    other operations.

    The check methods will raise errors if access is not allowed.
    They return no value.

    Example (for ``__getitem__``)::

           checker.check(ob, "__getitem__")
           return checker.proxy(ob[key])

    .. seealso:: :mod:`zope.security.checker`
    """

    def check_getattr(ob, name):
        """
        Check whether attribute access is allowed.

        If a checker implements ``__setitem__``, then ``__setitem__``
        will be called rather than ``check`` to ascertain whether an
        operation is allowed. This is a hack that allows significantly
        greater performance due to the fact that low-level operator
        access is much faster than method access.

        :raises: :class:`Unauthorized`
        :raises: :class:`Forbidden`
        :return: Nothing
        """

    def check_setattr(ob, name):
        """
        Check whether attribute assignment is allowed.

        If a checker implements ``__setitem__``, then ``__setitem__``
        will be called rather than ``check`` to ascertain whether an
        operation is allowed. This is a hack that allows significantly
        greater performance due to the fact that low-level operator
        access is much faster than method access.

        :raises: :class:`Unauthorized`
        :raises: :class:`Forbidden`
        :return: Nothing
        """

    def check(ob, operation):
        """
        Check whether *operation* is allowed.

        The operation name is the Python special method name,
        e.g. "__getitem__".

        May raise Unauthorized or Forbidden.  Returns no value.

        If a checker implements ``__setitem__``, then ``__setitem__``
        will be called rather than ``check`` to ascertain whether an
        operation is allowed. This is a hack that allows significantly
        greater performance due to the fact that low-level operator
        access is much faster than method access.

        :raises: :class:`Unauthorized`
        :raises: :class:`Forbidden`
        :return: Nothing
        """

    def proxy(value):
        """
        Return a security proxy for the *value*.

        If a checker implements ``__getitem__``, then ``__getitem__``
        will be called rather than ``proxy`` to proxy the value. This
        is a hack that allows significantly greater performance due to
        the fact that low-level operator access is much faster than
        method access.
        """


class INameBasedChecker(IChecker):
    """
    Security checker that uses permissions to check attribute
    access.
    """

    def permission_id(name):
        """
        Return the permission used to check attribute access on *name*.

        This permission is used by both :meth:`check` and
        :meth:`check_getattr`.
        """

    def setattr_permission_id(name):
        """
        Return the permission used to check attribute assignment on *name*.

        This permission is used by :meth:`check_setattr`.
        """


class ISecurityPolicy(Interface):
    """
    A factory to get :class:`IInteraction` objects.

    .. seealso:: :mod:`zope.security.simplepolicies`
       For default implementations.
    """

    def __call__(participation=None):
        """
        Creates and returns a new :class:`IInteraction` for a given
        request.

        If *participation* is not None, it is added to the new interaction.
        """


class IInteraction(Interface):
    """
    A representation of an interaction between some actors and the
    system.
    """

    participations = Attribute("""An iterable of participations.""")

    def add(participation):
        """Add a participation."""

    def remove(participation):
        """Remove a participation."""

    def checkPermission(permission, object):
        """Return whether security context allows permission on object.

        :param str permission: A permission name
        :param object: The object being accessed according to the permission
        :return: Whether the access is allowed or not.
        :rtype: bool
        """


class IParticipation(Interface):
    """
    A single participant in an interaction.
    """

    interaction = Attribute("The interaction")
    principal = Attribute("The authenticated :class:`IPrincipal`")


class NoInteraction(Exception):
    """No interaction started
    """


class IInteractionManagement(Interface):
    """
    Interaction management API.

    Every thread has at most one active interaction at a time.

    .. seealso:: :mod:`zope.security.management`
       That module provides the default implementation.
    """

    def newInteraction(participation=None):
        """
        Start a new interaction.

        If *participation* is not None, it is added to the new interaction.

        Raises an error if the calling thread already has an interaction.
        """

    def queryInteraction():
        """
        Return the current interaction.

        Return None if there is no interaction.
        """

    def getInteraction():
        """
        Return the current interaction.

        :raise NoInteraction: if there isn't a current interaction.
        """

    def endInteraction():
        """
        End the current interaction.

        Does nothing if there is no interaction.
        """


class IPrincipal(Interface):
    """
    Principals are security artifacts that execute actions in a
    security environment.

    The most common examples of principals include user and group
    objects.

    It is likely that ``IPrincipal`` objects will have associated
    views used to list principals in management interfaces. For
    example, a system in which other meta-data are provided for
    principals might extend ``IPrincipal`` and register a view for the
    extended interface that displays the extended information.
    """

    id = TextLine(
        title=_("Id"),
        description=_("The unique identification of the principal."),
        required=True,
        readonly=True)

    title = TextLine(
        title=_("Title"),
        description=_("The title of the principal. "
                      "This is usually used in the UI."),
        required=False)

    description = Text(
        title=_("Description"),
        description=_("A detailed description of the principal."),
        required=False)


class ISystemPrincipal(IPrincipal):
    """
    A principal that represents the system (application) itself.

    Typically a system principal is granted extra capabilities
    or excluded from certain checks. End users should *not* be able
    to act as the system principal.

    Because speed is often a factor, a single instance of a system principal
    is found at ``zope.security.management.system_user`` and can
    be compared for by identity (e.g., ``if principal is system_user:``).
    """


class IGroupAwarePrincipal(IPrincipal):
    """
    Group aware principal interface.

    Extends ``IPrincipal`` to contain direct group information.
    """

    groups = Attribute(
        'An iterable of :class:`IGroup` objects to which the principal'
        ' directly belongs')


class IGroupClosureAwarePrincipal(IGroupAwarePrincipal):
    """
    A group-aware principal that can recursively flatten the membership
    of groups to return all the groups.
    """

    allGroups = Attribute(
        "An iterable of the full closure of the principal's groups.")


class IGroup(IPrincipal):
    """
    Group of principals
    """


class IMemberGetterGroup(IGroup):
    """
    A group that can get its members.
    """

    def getMembers():
        """Return an iterable of the members of the group"""


class IMemberAwareGroup(IMemberGetterGroup):
    """
    A group that can both set and get its members.
    """

    def setMembers(value):
        """
        Set members of group to the principal IDs in the iterable
        *value*.
        """


class IPermission(Interface):
    """A permission object.

    Note that the ZCML ``<permission>`` directive restricts the ``id`` to
    be an identifier (a dotted name or a URI), but this interface allows
    any native string.
    """

    id = NativeStringLine(
        title=_("Id"),
        description=_("Id as which this permission will be known and used."),
        readonly=True,
        required=True)

    title = TextLine(
        title=_("Title"),
        description=_("Provides a title for the permission."),
        required=True)

    description = Text(
        title=_("Description"),
        description=_("Provides a description for the permission."),
        required=False)
