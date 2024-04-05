#############################################################################
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
""" Register class directive.
"""
__docformat__ = 'restructuredtext'

from types import ModuleType

from zope.component.factory import Factory
from zope.component.interface import provideInterface
from zope.component.interfaces import IFactory
from zope.component.zcml import utility
from zope.configuration.exceptions import ConfigurationError
from zope.interface import classImplements
from zope.schema.interfaces import IField

from zope.security.checker import Checker
from zope.security.checker import CheckerPublic
from zope.security.checker import defineChecker
from zope.security.checker import moduleChecker
from zope.security.interfaces import PUBLIC_PERMISSION_NAME as PublicPermission
from zope.security.protectclass import protectLikeUnto
from zope.security.protectclass import protectName
from zope.security.protectclass import protectSetAttribute


def dottedName(klass):
    if klass is None:
        return 'None'
    return klass.__module__ + '.' + klass.__name__


class ProtectionDeclarationException(Exception):
    """Security-protection-specific exceptions."""
    pass


class ClassDirective:

    def __init__(self, _context, class_):
        self.__id = dottedName(class_)  # this would barf on a module, anyway
        self.__class = class_
        if isinstance(self.__class, ModuleType):  # pragma: no cover
            raise ConfigurationError('Content class attribute must be a class')
        self.__context = _context

    def implements(self, _context, interface):
        for interface in interface:
            _context.action(
                discriminator=(
                    'ContentDirective', self.__class, object()),
                callable=classImplements,
                args=(self.__class, interface),
            )
            _context.action(
                discriminator=None,
                callable=provideInterface,
                args=(interface.__module__ + '.' + interface.getName(),
                      interface)
            )

    def require(self, _context,
                permission=None, attributes=None, interface=None,
                like_class=None, set_attributes=None, set_schema=None):
        """Require a permission to access a specific aspect"""
        if like_class:
            self.__mimic(_context, like_class)

        if not (interface or attributes or set_attributes or set_schema):
            if like_class:
                return
            raise ConfigurationError("Nothing required")

        if not permission:
            raise ConfigurationError("No permission specified")

        if interface:
            for i in interface:
                if i:
                    self.__protectByInterface(i, permission)
        if attributes:
            self.__protectNames(attributes, permission)
        if set_attributes:
            self.__protectSetAttributes(set_attributes, permission)
        if set_schema:
            for s in set_schema:
                self.__protectSetSchema(s, permission)

    def __mimic(self, _context, class_):
        """Base security requirements on those of the given class"""
        _context.action(
            discriminator=('mimic', self.__class, object()),
            callable=protectLikeUnto,
            args=(self.__class, class_),
        )

    def allow(self, _context, attributes=None, interface=None):
        """Like require, but with permission_id zope.Public"""
        return self.require(_context, PublicPermission, attributes, interface)

    def __protectByInterface(self, interface, permission_id):
        "Set a permission on names in an interface."
        for n, d in sorted(interface.namesAndDescriptions(1)):
            self.__protectName(n, permission_id)
        self.__context.action(
            discriminator=None,
            callable=provideInterface,
            args=(interface.__module__ + '.' + interface.getName(),
                  interface)
        )

    def __protectName(self, name, permission_id):
        "Set a permission on a particular name."
        self.__context.action(
            discriminator=('protectName', self.__class, name),
            callable=protectName,
            args=(self.__class, name, permission_id)
        )

    def __protectNames(self, names, permission_id):
        "Set a permission on a bunch of names."
        for name in names:
            self.__protectName(name, permission_id)

    def __protectSetAttributes(self, names, permission_id):
        "Set a permission on a bunch of names."
        for name in names:
            self.__context.action(
                discriminator=('protectSetAttribute', self.__class, name),
                callable=protectSetAttribute,
                args=(self.__class, name, permission_id)
            )

    def __protectSetSchema(self, schema, permission_id):
        "Set a permission on a bunch of names."
        _context = self.__context
        for name in sorted(schema):
            field = schema[name]
            if IField.providedBy(field) and not field.readonly:
                _context.action(
                    discriminator=('protectSetAttribute', self.__class, name),
                    callable=protectSetAttribute,
                    args=(self.__class, name, permission_id)
                )
        _context.action(
            discriminator=None,
            callable=provideInterface,
            args=(schema.__module__ + '.' + schema.getName(),
                  schema)
        )

    def __call__(self):
        "Handle empty/simple declaration."
        return ()

    def factory(self, _context, id=None, title="", description=''):
        """Register a zmi factory for this class"""

        id = id or self.__id
        factoryObj = Factory(self.__class, title, description)

        # note factories are all in one pile, utilities and content,
        # so addable names must also act as if they were all in the
        # same namespace, despite the utilities/content division
        utility(_context, IFactory, factoryObj,
                permission=PublicPermission, name=id)


def protectModule(module, name, permission):
    """Set up a module checker to require a permission to access a name

    If there isn't a checker for the module, create one.
    """

    checker = moduleChecker(module)
    if checker is None:
        checker = Checker({}, {})
        defineChecker(module, checker)

    if permission == PublicPermission:
        # Translate public permission to CheckerPublic
        permission = CheckerPublic

    # We know a dictionary get method was used because we set it
    protections = checker.get_permissions
    protections[name] = permission


def _names(attributes, interfaces):
    seen = {}
    for name in attributes:
        if name not in seen:
            seen[name] = 1
            yield name
    for interface in interfaces:
        for name in interface:
            if name not in seen:
                seen[name] = 1
                yield name


def allow(context, attributes=(), interface=()):

    for name in _names(attributes, interface):
        context.action(
            discriminator=('http://namespaces.zope.org/zope:module',
                           context.module, name),
            callable=protectModule,
            args=(context.module, name, PublicPermission),
        )


def require(context, permission, attributes=(), interface=()):
    for name in _names(attributes, interface):
        context.action(
            discriminator=('http://namespaces.zope.org/zope:module',
                           context.module, name),
            callable=protectModule,
            args=(context.module, name, permission),
        )
