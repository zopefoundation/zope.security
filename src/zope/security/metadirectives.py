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
"""Component architecture related 'zope' ZCML namespace directive interfaces
"""
__docformat__ = 'restructuredtext'

import zope.configuration.fields
import zope.interface
import zope.schema
from zope.configuration.fields import GlobalInterface
from zope.configuration.fields import GlobalObject
from zope.configuration.fields import PythonIdentifier
from zope.configuration.fields import Tokens
from zope.interface import Interface

import zope.security.zcml
from zope.security.i18n import ZopeMessageFactory as _
from zope.security.zcml import Permission


class IClassDirective(zope.interface.Interface):
    """Make statements about a class"""

    class_ = zope.configuration.fields.GlobalObject(
        title=_("Class"),
        required=True
    )


class IImplementsSubdirective(zope.interface.Interface):
    """Declare that the class given by the content directive's class
    attribute implements a given interface
    """

    interface = zope.configuration.fields.Tokens(
        title=_("One or more interfaces"),
        required=True,
        value_type=zope.configuration.fields.GlobalInterface()
    )


class IRequireSubdirective(zope.interface.Interface):
    """Indicate that the a specified list of names or the names in a
    given Interface require a given permission for access.
    """

    permission = zope.security.zcml.Permission(
        title=_("Permission"),
        description=_("""
        Specifies the permission by id that will be required to
        access or mutate the attributes and methods specified."""),
        required=False,
    )

    attributes = zope.configuration.fields.Tokens(
        title=_("Attributes and methods"),
        description=_("This is a list of attributes and methods"
                      " that can be accessed."),
        required=False,
        value_type=zope.configuration.fields.PythonIdentifier(),
    )

    set_attributes = zope.configuration.fields.Tokens(
        title=_("Attributes that can be set"),
        description=_("This is a list of attributes that can be"
                      " modified/mutated."),
        required=False,
        value_type=zope.configuration.fields.PythonIdentifier(),
    )

    interface = zope.configuration.fields.Tokens(
        title=_("Interfaces"),
        description=_("The listed interfaces' methods and attributes"
                      " can be accessed."),
        required=False,
        value_type=zope.configuration.fields.GlobalInterface(),
    )

    set_schema = zope.configuration.fields.Tokens(
        title=_("The attributes specified by the schema can be set"),
        description=_("The listed schemas' properties can be"
                      " modified/mutated."),
        required=False,
        value_type=zope.configuration.fields.GlobalInterface(),
    )

    like_class = zope.configuration.fields.GlobalObject(
        title=_("Configure like this class"),
        description=_("""
        This argument says that this content class should be configured in the
        same way the specified class' security is. If this argument is
        specified, no other argument can be used."""),
        required=False,
    )


class IAllowSubdirective(zope.interface.Interface):
    """
    Declare a part of the class to be publicly viewable (that is,
    requires the zope.Public permission). Only one of the following
    two attributes may be used.
    """

    attributes = zope.configuration.fields.Tokens(
        title=_("Attributes"),
        required=False,
        value_type=zope.configuration.fields.PythonIdentifier(),
    )

    interface = zope.configuration.fields.Tokens(
        title=_("Interface"),
        required=False,
        value_type=zope.configuration.fields.GlobalInterface(),
    )


class IFactorySubdirective(zope.interface.Interface):
    """Specify the factory used to create this content object"""

    id = zope.schema.Id(
        title=_("ID"),
        description=_("""
        the identifier for this factory in the ZMI factory
        identification scheme.  If not given, defaults to the literal
        string given as the content directive's 'class' attribute."""),
        required=False,
    )

    title = zope.configuration.fields.MessageID(
        title=_("Title"),
        description=_("Text suitable for use in the 'add content' menu"
                      " of a management interface"),
        required=False,
    )

    description = zope.configuration.fields.MessageID(
        title=_("Description"),
        description=_("Longer narrative description of what this"
                      " factory does"),
        required=False,
    )


class IModule(Interface):
    """Group security declarations about a module"""

    module = GlobalObject(
        title=u"Module",
        description=u"Pointer to the module object.",
        required=True)


class IAllow(Interface):
    """Allow access to selected module attributes

    Access is unconditionally allowed to any names provided directly
    in the attributes attribute or to any names defined by
    interfaces listed in the interface attribute.
    """

    attributes = Tokens(
        title=u"Attributes",
        description=u"The attributes to provide access to.",
        value_type=PythonIdentifier(),
        required=False)

    interface = Tokens(
        title=u"Interface",
        description=(u"Interfaces whos names to provide access to. Access "
                     u"will be provided to all of the names defined by the "
                     u"interface(s). Multiple interfaces can be supplied."),
        value_type=GlobalInterface(),
        required=False)


class IRequire(Interface):
    """Require a permission to access selected module attributes

    The given permission is required to access any names provided
    directly in the attributes attribute or any names defined by
    interfaces listed in the interface attribute.
    """

    attributes = Tokens(
        title=u"Attributes",
        description=u"The attributes to require permission for.",
        value_type=PythonIdentifier(),
        required=False)

    permission = Permission(
        title=u"Permission ID",
        description=u"The ID of the permission to require.")
