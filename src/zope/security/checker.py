##############################################################################
#
# Copyright (c) 2003 Zope Foundation and Contributors.
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
Security Checkers.

This module contains the primary implementations of
:class:`zope.security.interfaces.IChecker` (:class:`Checker`,
:class:`MultiChecker`, :func:`NamesChecker`) and
:class:`zope.security.interfaces.IProxyFactory` (:func:`ProxyFactory`).

It also defines helpers for permission checking (:func:`canAccess`,
:func:`canWrite`) and getting checkers
(:func:`getCheckerForInstancesOf`, :func:`selectChecker`).

This module is accelerated with a C implementation on CPython by
default. If the environment variable ``PURE_PYTHON`` is set (to any
value) before this module is imported, the C extensions will be
bypassed and the reference Python implementations will be used. This
can be helpful for debugging and tracing.

Debugging Permissions Problems
==============================

You can set the environment variable ``ZOPE_WATCH_CHECKERS`` before
this module is imported to get additional security checker debugging
output on the standard error.

Setting ``ZOPE_WATCH_CHECKERS`` to 1 will display messages about unauthorized
or forbidden attribute access.  Setting it to a larger number will also display
messages about granted attribute access.

Note that the ``ZOPE_WATCH_CHECKERS`` mechanism may eventually be
replaced with a more general security auditing mechanism.

.. seealso:: :class:`CheckerLoggingMixin`
.. seealso:: :class:`WatchingChecker`
.. seealso:: :class:`WatchingCombinedChecker`

API
===

.. py:data:: CheckerPublic

  The special constant that indicates that no permission
  checking needs to be done.

.. autofunction:: selectChecker
"""
import abc
import datetime
import decimal
import os
import sys
import types
import weakref

import zope.interface.declarations
import zope.interface.interface
import zope.interface.interfaces
from zope.i18nmessageid import Message
from zope.interface import Interface
from zope.interface import directlyProvides
from zope.interface import implementer
from zope.interface.interfaces import IDeclaration
from zope.interface.interfaces import IInterface

from zope.security._compat import CLASS_TYPES
from zope.security._compat import PURE_PYTHON
from zope.security._compat import PYTHON2
from zope.security._compat import implementer_if_needed
from zope.security._definitions import thread_local
from zope.security.interfaces import ForbiddenAttribute
from zope.security.interfaces import IChecker
from zope.security.interfaces import INameBasedChecker
from zope.security.interfaces import ISecurityProxyFactory
from zope.security.interfaces import Unauthorized
from zope.security.proxy import Proxy
from zope.security.proxy import getChecker


try:
    from zope.exceptions import DuplicationError
except ImportError:  # pragma: no cover
    class DuplicationError(Exception):
        """A duplicate registration was attempted"""

WATCH_CHECKERS = 0

if os.environ.get('ZOPE_WATCH_CHECKERS'):  # pragma: no cover
    try:
        WATCH_CHECKERS = int(os.environ.get('ZOPE_WATCH_CHECKERS'))
    except ValueError:
        WATCH_CHECKERS = 1


def ProxyFactory(object, checker=None):
    """Factory function that creates a proxy for an object

    The proxy checker is looked up if not provided.
    """
    if type(object) is Proxy:
        if checker is None or checker is getChecker(object):
            return object
        else:
            # We have a proxy, but someone asked us to change its checker.
            # Let's raise an exception.
            #
            # Other reasonable actions would be to either keep the existing
            # proxy, or to create a new one with the given checker.
            # The latter might be a security hole though, if untrusted code
            # can call ProxyFactory.
            raise TypeError("Tried to use ProxyFactory to change a Proxy's"
                            " checker.")
    if checker is None:
        checker = getattr(object, '__Security_checker__', None)

        if checker is None:
            checker = selectChecker(object)
            if checker is None:
                return object

    return Proxy(object, checker)


directlyProvides(ProxyFactory, ISecurityProxyFactory)

# This import represents part of the API for the proxy module
from . import proxy  # noqa: E402 module level import not at top


proxy.ProxyFactory = ProxyFactory


def canWrite(obj, name):
    """Check whether the interaction may write an attribute named name on obj.

    Convenience method.  Rather than using checkPermission in high level code,
    use canWrite and canAccess to avoid binding code to permissions.
    """
    obj = ProxyFactory(obj)
    checker = getChecker(obj)
    try:
        checker.check_setattr(obj, name)
    except Unauthorized:
        return False
    except ForbiddenAttribute:
        # we are going to be a bit DWIM-y here: see
        # http://www.zope.org/Collectors/Zope3-dev/506

        # generally, if the check is ForbiddenAttribute we want it to be
        # raised: it probably indicates a programming or configuration error.
        # However, we special case a write ForbiddenAttribute when one can
        # actually read the attribute: this represents a reasonable
        # configuration of a readonly attribute, and returning False (meaning
        # "no, you can't write it") is arguably more useful than raising the
        # exception.
        try:
            checker.check_getattr(obj, name)
            # we'll let *this* ForbiddenAttribute fall through, if any.  It
            # means that both read and write are forbidden.
        except Unauthorized:
            pass
        return False
    # all other exceptions, other than Unauthorized and ForbiddenAttribute,
    # should be passed through uncaught, as they indicate programmer error
    return True


def canAccess(obj, name):
    """Check whether the interaction may access an attribute named name on obj.

    Convenience method.  Rather than using checkPermission in high level code,
    use canWrite and canAccess to avoid binding code to permissions.
    """
    # access attributes and methods, including, in the current checker
    # implementation, special names like __getitem__
    obj = ProxyFactory(obj)
    checker = getChecker(obj)
    try:
        checker.check_getattr(obj, name)
    except Unauthorized:
        return False
    # if it is Forbidden (or anything else), let it be raised: it probably
    # indicates a programming or configuration error
    return True


@implementer(INameBasedChecker)
class CheckerPy(object):
    """
    The Python reference implementation of
    :class:`zope.security.interfaces.INameBasedChecker`.

    Ordinarily there will be no reason to ever explicitly use this class;
    instead use the class assigned to :class:`Checker`.
    """

    def __init__(self, get_permissions, set_permissions=None):
        """Create a checker

        A dictionary must be provided for computing permissions for
        names. The dictionary get will be called with attribute names
        and must return a permission ID, None, or the special marker,
        :const:`CheckerPublic`. If None is returned, then access to the name is
        forbidden. If :const:`CheckerPublic` is returned, then access will be
        granted without checking a permission.

        An optional setattr dictionary may be provided for checking
        set attribute access.

        """
        if not isinstance(get_permissions, dict):
            raise TypeError('get_permissions must be a dict')
        self.get_permissions = get_permissions
        if set_permissions is not None:
            if not isinstance(set_permissions, dict):
                raise TypeError('set_permissions must be a dict')
        else:
            set_permissions = {}
        self.set_permissions = set_permissions

    def permission_id(self, name):
        'See INameBasedChecker'
        return self.get_permissions.get(name)

    def setattr_permission_id(self, name):
        'See INameBasedChecker'
        if self.set_permissions:
            return self.set_permissions.get(name)

    def check_setattr(self, object, name):
        'See IChecker'
        if self.set_permissions:
            permission = self.set_permissions.get(name)
        else:
            permission = None

        if permission is not None:
            if permission is CheckerPublic:
                return  # Public
            if thread_local.interaction.checkPermission(permission, object):
                return  # allowed
            else:
                __traceback_supplement__ = (TracebackSupplement, object)
                raise Unauthorized(object, name, permission)

        __traceback_supplement__ = (TracebackSupplement, object)
        raise ForbiddenAttribute(name, object)

    def check(self, object, name):
        'See IChecker'
        permission = self.get_permissions.get(name)
        if permission is not None:
            if permission is CheckerPublic:
                return  # Public
            if thread_local.interaction.checkPermission(permission, object):
                return
            else:
                __traceback_supplement__ = (TracebackSupplement, object)
                raise Unauthorized(object, name, permission)
        elif name in _available_by_default:
            return

        if name != '__iter__' or hasattr(object, name):
            __traceback_supplement__ = (TracebackSupplement, object)
            raise ForbiddenAttribute(name, object)

    check_getattr = check  # 'See IChecker'

    def proxy(self, value):
        'See IChecker'
        if type(value) is Proxy:
            return value
        checker = getattr(value, '__Security_checker__', None)
        if checker is None:
            checker = selectChecker(value)
            if checker is None:
                return value

        return Proxy(value, checker)


Checker = CheckerPy  # in case no C optimizations


# Helper class for __traceback_supplement__
class TracebackSupplement(object):

    def __init__(self, obj):
        self.obj = obj

    def getInfo(self):
        result = []
        try:
            cls = self.obj.__class__
            if hasattr(cls, "__module__"):
                s = "%s.%s" % (cls.__module__, cls.__name__)
            else:  # pragma: no cover XXX
                s = str(cls.__name__)
            result.append("   - class: " + s)
        except:  # pragma: no cover # noqa: E722 do not use bare 'except'
            pass
        try:
            cls = type(self.obj)
            if hasattr(cls, "__module__"):
                s = "%s.%s" % (cls.__module__, cls.__name__)
            else:  # pragma: no cover XXX
                s = str(cls.__name__)
            result.append("   - type: " + s)
        except:  # pragma: no cover # noqa: E722 do not use bare 'except'
            pass
        return "\n".join(result)


class Global(object):
    """A global object that behaves like a string.

    We want this to behave as a global, meaning it's pickled
    by name, rather than value. We need to arrange that it has a suitable
    __reduce__.
    """

    def __init__(self, name, module=None):
        if module is None:  # pragma: no cover XXX
            module = sys._getframe(1).f_locals['__name__']

        self.__name__ = name
        self.__module__ = module

    def __reduce__(self):
        return self.__name__

    def __repr__(self):
        return "%s(%s,%s)" % (self.__class__.__name__,
                              self.__name__, self.__module__)


CheckerPublic = Global('CheckerPublic')
CP_HACK_XXX = CheckerPublic

# Now we wrap it in a security proxy so that it retains its
# identity when it needs to be security proxied.
# XXX: This means that we can't directly document it with
# sphinx because issubclass() will fail.
d = {}
CheckerPublic = Proxy(CheckerPublic, Checker(d))  # XXX uses CheckerPy
d['__reduce__'] = CheckerPublic
d['__module__'] = CheckerPublic
del d

# TODO: It's a bit scary above that we can pickle a proxy if access is
# granted to __reduce__. We might want to bother to prevent this in
# general and only allow it in this specific case.


def NamesChecker(names=(), permission_id=CheckerPublic, **__kw__):
    """Return a checker that grants access to a set of names.

    A sequence of names is given as the first argument. If a second
    argument, permission_id, is given, it is the permission required
    to access the names.  Additional names and permission IDs can be
    supplied as keyword arguments.
    """

    data = {}
    data.update(__kw__)
    for name in names:
        if data.get(name, permission_id) is not permission_id:
            raise DuplicationError(name)
        data[name] = permission_id

    return Checker(data)


def InterfaceChecker(interface, permission_id=CheckerPublic, **__kw__):
    """
    Create a :func:`NamesChecker` for all the names defined in the *interface*
    (a subclass of :class:`zope.interface.Interface`).
    """
    return NamesChecker(interface.names(all=True), permission_id, **__kw__)


def MultiChecker(specs):
    """
    Create a checker from a sequence of specifications

    A specification is:

    - A two-tuple with:

      o a sequence of names or an interface

      o a permission ID

      All the names in the sequence of names or the interface are
      protected by the permission.

    - A dictionary (having an items method), with items that are
      name/permission-id pairs.
    """
    data = {}

    for spec in specs:
        if type(spec) is tuple:
            names, permission_id = spec
            if IInterface.providedBy(names):
                names = names.names(all=True)
            for name in names:
                if data.get(name, permission_id) is not permission_id:
                    raise DuplicationError(name)
                data[name] = permission_id
        else:
            for name, permission_id in spec.items():
                if data.get(name, permission_id) is not permission_id:
                    raise DuplicationError(name)
                data[name] = permission_id

    return Checker(data)


def selectCheckerPy(object):
    """Get a checker for the given object

    The appropriate checker is returned or None is returned. If the
    return value is None, then object should not be wrapped in a proxy.
    """

    # We need to be careful here. We might have a proxy, in which case
    # we can't use the type.  OTOH, we might not be able to use the
    # __class__ either, since not everything has one.

    # TODO: we really need formal proxy introspection

    # if type(object) is Proxy:
    #    # Is this already a security proxy?
    #    return None

    checker = _getChecker(type(object), _defaultChecker)

    # checker = _getChecker(getattr(object, '__class__', type(object)),
    #                      _defaultChecker)

    if checker is NoProxy:
        return None

    while not isinstance(checker, Checker):
        checker = checker(object)

        if checker is NoProxy or checker is None:
            return None

    return checker


selectChecker = selectCheckerPy  # in case no C optimizations


def getCheckerForInstancesOf(class_):
    return _checkers.get(class_)


DEFINABLE_TYPES = CLASS_TYPES + (types.ModuleType,)


def defineChecker(type_, checker):
    """Define a checker for a given type of object

    The checker can be a :class:`Checker`, or a function that, when called with
    an object, returns a :class:`Checker`.
    """
    if not isinstance(type_, DEFINABLE_TYPES):
        raise TypeError(
            'type_ must be a type, class or module, not a %s' % type_)
    if type_ in _checkers:
        raise DuplicationError(type_)
    _checkers[type_] = checker


def undefineChecker(type_):
    del _checkers[type_]


NoProxy = object()

# _checkers is a mapping.
#
#  - Keys are types
#
#  - Values are
#
#    o None => rock
#    o a Checker
#    o a function returning None or a Checker
#
_checkers = {}

_defaultChecker = Checker({})
_available_by_default = []

# Get optimized versions
_c_available = not PURE_PYTHON
if _c_available:  # pragma: no cover
    try:
        import zope.security._zope_security_checker
    except (ImportError, AttributeError):
        _c_available = False

if _c_available:  # pragma: no cover
    from zope.security._zope_security_checker import Checker
    from zope.security._zope_security_checker import NoProxy
    from zope.security._zope_security_checker import _available_by_default
    from zope.security._zope_security_checker import _checkers
    from zope.security._zope_security_checker import _defaultChecker
    from zope.security._zope_security_checker import selectChecker
    zope.interface.classImplements(Checker, INameBasedChecker)


_getChecker = _checkers.get


@implementer_if_needed(IChecker)
class CombinedChecker(Checker):
    """A checker that combines two other checkers in a logical-or fashion.

    The following table describes the result of a combined checker in detail.

    +--------------------+--------------------+-------------------------------------+
    | checker1           | checker2           | CombinedChecker(checker1, checker2) |
    +====================+====================+=====================================+
    | ok                 | anything           | ok (checker 2 never called)         |
    +--------------------+--------------------+-------------------------------------+
    | Unauthorized       | ok                 | ok                                  |
    +--------------------+--------------------+-------------------------------------+
    | Unauthorized       | Unauthorized       | Unauthorized                        |
    +--------------------+--------------------+-------------------------------------+
    | Unauthorized       | ForbiddenAttribute | Unauthorized                        |
    +--------------------+--------------------+-------------------------------------+
    | ForbiddenAttribute | ok                 | ok                                  |
    +--------------------+--------------------+-------------------------------------+
    | ForbiddenAttribute | Unauthorized       | Unauthorized                        |
    +--------------------+--------------------+-------------------------------------+
    | ForbiddenAttribute | ForbiddenAttribute | ForbiddenAttribute                  |
    +--------------------+--------------------+-------------------------------------+
    """  # noqa: E501 line too long

    def __init__(self, checker1, checker2):
        """Create a combined checker."""
        Checker.__init__(self,
                         checker1.get_permissions,
                         checker1.set_permissions)

        self._checker2 = checker2

    def check(self, object, name):
        'See IChecker'
        try:
            Checker.check(self, object, name)
        except ForbiddenAttribute:
            self._checker2.check(object, name)
        except Unauthorized as unauthorized_exception:
            try:
                self._checker2.check(object, name)
            except ForbiddenAttribute:
                raise unauthorized_exception

    check_getattr = __setitem__ = check

    def check_setattr(self, object, name):
        'See IChecker'
        try:
            Checker.check_setattr(self, object, name)
        except ForbiddenAttribute:
            self._checker2.check_setattr(object, name)
        except Unauthorized as unauthorized_exception:
            try:
                self._checker2.check_setattr(object, name)
            except ForbiddenAttribute:
                raise unauthorized_exception


class CheckerLoggingMixin(object):
    """
    Debugging mixin for checkers.

    Prints verbose debugging information about every performed check to
    :data:`sys.stderr`.

    """

    #: If set to 1 (the default), only displays ``Unauthorized`` and
    #: ``Forbidden`` messages. If verbosity is set to a larger number,
    #: displays all messages. Normally this is controlled via the environment
    #: variable ``ZOPE_WATCH_CHECKERS``.
    verbosity = 1
    _file = sys.stderr

    def _log(self, msg, verbosity=1):
        if self.verbosity >= verbosity:
            self._file.write('%s\n' % msg)

    def check(self, object, name):
        try:
            super(CheckerLoggingMixin, self).check(object, name)
            if self.verbosity > 1:
                if name in _available_by_default:
                    self._log('[CHK] + Always available: %s on %r'
                              % (name, object), 2)
                else:
                    self._log(
                        '[CHK] + Granted: %s on %r' % (name, object), 2)
        except Unauthorized:
            self._log(
                '[CHK] - Unauthorized: %s on %r' % (name, object))
            raise
        except ForbiddenAttribute:
            self._log(
                '[CHK] - Forbidden: %s on %r' % (name, object))
            raise

    def check_getattr(self, object, name):
        try:
            super(CheckerLoggingMixin, self).check(object, name)
            if self.verbosity > 1:
                if name in _available_by_default:
                    self._log(
                        '[CHK] + Always available getattr: %s on %r'
                        % (name, object), 2)
                else:
                    self._log(
                        '[CHK] + Granted getattr: %s on %r'
                        % (name, object), 2)
        except Unauthorized:
            self._log(
                '[CHK] - Unauthorized getattr: %s on %r' % (name, object))
            raise
        except ForbiddenAttribute:
            self._log(
                '[CHK] - Forbidden getattr: %s on %r' % (name, object))
            raise

    __setitem__ = check_getattr

    def check_setattr(self, object, name):
        try:
            super(CheckerLoggingMixin, self).check_setattr(object, name)
            if self.verbosity > 1:
                self._log(
                    '[CHK] + Granted setattr: %s on %r' % (name, object), 2)
        except Unauthorized:
            self._log(
                '[CHK] - Unauthorized setattr: %s on %r' % (name, object))
            raise
        except ForbiddenAttribute:
            self._log(
                '[CHK] - Forbidden setattr: %s on %r' % (name, object))
            raise


# We have to be careful with the order of inheritance
# here. See https://github.com/zopefoundation/zope.security/issues/8
class WatchingChecker(CheckerLoggingMixin, Checker):
    """
    A checker that will perform verbose logging. This will be set
    as the default when ``ZOPE_WATCH_CHECKERS`` is set when this
    module is imported.
    """
    verbosity = WATCH_CHECKERS


class WatchingCombinedChecker(CombinedChecker, WatchingChecker):
    """
    A checker that will perform verbose logging. This will be set
    as the default when ``ZOPE_WATCH_CHECKERS`` is set when this
    module is imported.
    """
    verbosity = WATCH_CHECKERS


if WATCH_CHECKERS:  # pragma: no cover
    # When we make these the default, we also need to be sure
    # to update the _defaultChecker's type (if it's not the C
    # extension) so that selectCheckerPy can properly recognize
    # it as a Checker.
    # See https://github.com/zopefoundation/zope.security/issues/8
    Checker = WatchingChecker
    CombinedChecker = WatchingCombinedChecker

    if not _c_available:
        _defaultChecker.__class__ = Checker


def _instanceChecker(inst):
    return _checkers.get(inst.__class__, _defaultChecker)


def moduleChecker(module):
    """
    Return the :class:`zope.security.interfaces.IChecker` defined for the
    *module*, if any.

    .. seealso:: :func:`zope.security.metaconfigure.protectModule`
       To define module protections.
    """
    return _checkers.get(module)


_available_by_default[:] = [
    '__lt__', '__le__', '__eq__',
    '__gt__', '__ge__', '__ne__',
    '__hash__', '__nonzero__',
    '__class__', '__providedBy__', '__implements__',
    '__repr__', '__conform__',
    '__name__', '__parent__',
]

_callableChecker = NamesChecker(['__str__', '__name__', '__call__'])
_typeChecker = NamesChecker([
    '__str__', '__name__', '__module__', '__bases__', '__mro__',
    '__implemented__',
])
_namedChecker = NamesChecker(['__name__'])
_iteratorChecker = NamesChecker([
    'next', '__next__', '__iter__', '__len__',
    '__length_hint__',
])

_setChecker = NamesChecker([
    '__iter__', '__len__', '__str__', '__contains__',
    'copy', 'difference', 'intersection', 'issubset',
    'issuperset', 'symmetric_difference', 'union',
    '__and__', '__or__', '__sub__', '__xor__',
    '__rand__', '__ror__', '__rsub__', '__rxor__',
    '__eq__', '__ne__', '__lt__', '__gt__',
    '__le__', '__ge__',
])


class _BasicTypes(dict):
    """Basic Types Dictionary

    Make sure that checkers are really updated, when a new type is added.
    """

    def __setitem__(self, name, value):
        dict.__setitem__(self, name, value)
        _checkers[name] = value

    def __delitem__(self, name):
        dict.__delitem__(self, name)
        del _checkers[name]

    def clear(self):
        # Make sure you cannot clear the values
        raise NotImplementedError

    def update(self, d):
        dict.update(self, d)
        _checkers.update(d)


_basic_types = {
    object: NoProxy,
    int: NoProxy,
    float: NoProxy,
    complex: NoProxy,
    type(None): NoProxy,
    str: NoProxy,
    bytes: NoProxy,
    Message: NoProxy,  # Messages are immutable, so it's okay
    bool: NoProxy,
    datetime.timedelta: NoProxy,
    datetime.datetime: NoProxy,
    datetime.date: NoProxy,
    datetime.time: NoProxy,
    datetime.tzinfo: NoProxy,
}
if PYTHON2:  # pragma: no cover
    _basic_types[long] = NoProxy  # noqa: F821 undefined name 'long'
    _basic_types[unicode] = NoProxy  # noqa: F821 undefined name 'unicode'
else:
    _basic_types[type({}.values())] = NoProxy
    _basic_types[type({}.keys())] = NoProxy
    _basic_types[type({}.items())] = NoProxy

try:
    import pytz
except ImportError:  # pragma: no cover
    pass
else:
    _basic_types[type(pytz.UTC)] = NoProxy

BasicTypes = _BasicTypes(_basic_types)
del _basic_types

# Available for tests. Located here so it can be kept in sync with BasicTypes.
BasicTypes_examples = {
    object: object(),
    int: 65536,
    float: -1.4142,
    complex: -1.4142j,
    type(None): None,
    bytes: b'abc',
    bool: True,
    datetime.timedelta: datetime.timedelta(3),
    datetime.datetime: datetime.datetime(2003, 1, 1),
    datetime.date: datetime.date(2003, 1, 1),
    datetime.time: datetime.time(23, 58),
    Message: Message('message', domain='hello')
}

if PYTHON2:  # pragma: no cover
    BasicTypes_examples[unicode] = u'uabc'  # noqa: F821 undefined name
    BasicTypes_examples[long] = long(65536)  # noqa: F821 undefined name


class _Sequence(object):
    def __len__(self):
        raise NotImplementedError()

    def __getitem__(self, i):
        raise NotImplementedError()


_Declaration_checker = InterfaceChecker(
    IDeclaration,
    _implied=CheckerPublic,
    subscribe=CheckerPublic,
    unsubscribe=CheckerPublic,
    __call__=CheckerPublic,
)


def f():  # pragma: no cover
    yield f


_default_checkers = {
    dict: NamesChecker(['__getitem__', '__len__', '__iter__',
                        'get', 'has_key', 'copy', '__str__', 'keys',
                        'values', 'items', 'iterkeys', 'iteritems',
                        'itervalues', '__contains__']),
    list: NamesChecker(['__getitem__', '__getslice__', '__len__', '__iter__',
                        '__contains__', 'index', 'count', '__str__',
                        '__add__', '__radd__', ]),
    set: _setChecker,
    frozenset: _setChecker,
    # XXX: actually decimal.Decimal has more methods, which are unlisted here
    #      so expect ForbiddenAttribute on such
    decimal.Decimal: NamesChecker(['__nonzero__', '__cmp__', '__eq__',
                                   '__ne__', '__hash__',
                                   '__str__',
                                   '__neg__', '__pos__', '__abs__',
                                   '__add__', '__radd__',
                                   '__sub__', '__rsub__',
                                   '__mul__', '__rmul__',
                                   '__div__', '__truediv__',
                                   '__rdiv__', '__rtruediv__',
                                   '__divmod__', '__rdivmod__',
                                   '__mod__', '__rmod__',
                                   '__floordiv__', '__rfloordiv__',
                                   '__float__', '__int__', '__long__',
                                   '__pow__', '__rpow__',
                                   'adjusted', 'as_tuple', 'compare',
                                   'max', 'min', 'normalize',
                                   'quantize', 'remainder_near',
                                   'same_quantum', 'sqrt',
                                   'to_eng_string', 'to_integral']),

    # YAGNI: () a rock
    tuple: NamesChecker(['__getitem__', '__getslice__', '__add__', '__radd__',
                         '__contains__', '__len__', '__iter__',
                         '__str__']),
    Proxy: NoProxy,
    type(weakref.ref(_Sequence())): NamesChecker(['__call__']),
    types.FunctionType: _callableChecker,
    types.MethodType: _callableChecker,
    types.BuiltinFunctionType: _callableChecker,
    types.BuiltinMethodType: _callableChecker,
    # method-wrapper
    type(().__repr__): _callableChecker,
    type: _typeChecker,
    types.ModuleType: lambda module: _checkers.get(module, _namedChecker),
    type(iter([])): _iteratorChecker,  # Same types in Python 2.2.1,
    type(iter(())): _iteratorChecker,  # different in Python 2.3.
    type(iter({})): _iteratorChecker,
    type(iter(set())): _iteratorChecker,
    type(iter(_Sequence())): _iteratorChecker,
    type(f()): _iteratorChecker,
    type(Interface): InterfaceChecker(
        IInterface,
        __str__=CheckerPublic,
        _implied=CheckerPublic,
        subscribe=CheckerPublic,
        # To iterate, Python calls __len__ as a hint.
        # Python 2 ignores AttributeErrors, but Python 3
        # lets them pass.
        __len__=CheckerPublic,
    ),
    zope.interface.interface.Method: InterfaceChecker(
        zope.interface.interfaces.IMethod),
    zope.interface.declarations.ProvidesClass: _Declaration_checker,
    zope.interface.declarations.ClassProvides: _Declaration_checker,
    zope.interface.declarations.Implements: _Declaration_checker,
    zope.interface.declarations.Declaration: _Declaration_checker,
    abc.ABCMeta: _typeChecker,
}
if PYTHON2:  # pragma: no cover
    _default_checkers[types.ClassType] = _typeChecker
    _default_checkers[types.InstanceType] = _instanceChecker
    # slot description
    _default_checkers[type({}.iteritems())] = _iteratorChecker
    _default_checkers[type({}.iterkeys())] = _iteratorChecker
    _default_checkers[type({}.itervalues())] = _iteratorChecker


def _fixup_dictlike(dict_type):
    empty_dict = dict_type()
    populated_dict = dict_type({1: 2})
    for dictlike in (empty_dict, populated_dict):
        for attr in ('__iter__', 'keys', 'items', 'values'):
            obj = getattr(dictlike, attr)()
            o_type = type(obj)
            if o_type not in _default_checkers:
                _default_checkers[o_type] = _iteratorChecker
            # PyPy3 has special types for iter({}.items()) etc.
            iter_type = type(iter(obj))
            if iter_type not in _default_checkers:
                _default_checkers[iter_type] = _iteratorChecker


def _fixup_odict():
    # OrderedDicts have three different implementations: Python 2 (pure
    # python, returns generators and lists), Python <=3.4 (pure Python,
    # uses view classes) and CPython 3.5+ (implemented in C). These should
    # all be iterable.
    from collections import OrderedDict

    # The `_fixup_dictlike` is detected as undefined because it is deleted
    # later on but this function is called beforehand:
    _fixup_dictlike(OrderedDict)  # noqa: F821 undefined name '_fixup_dictlike'


_fixup_odict()
del _fixup_odict

try:
    import BTrees  # noqa: F401 'BTrees' imported but unused
except ImportError:  # pragma: no cover
    pass
else:
    # The C implementation of BTree.items() is its own iterator
    # and doesn't need any special entries to enable iteration.
    # But the Python implementation has to call __iter__ to be able
    # to do iteration. Whitelist it so that they behave the same.
    # In addition, Python 3 will attempt to call __len__ on iterators
    # for a length hint, so the C implementations also need to be
    # added to the _iteratorChecker. The same thing automatically
    # applies for .keys() and .values() since they return the same type.
    # We do this here so that all users of zope.security can benefit
    # without knowing implementation details.
    # See https://github.com/zopefoundation/zope.security/issues/20

    def _fixup_btrees():
        import BTrees._base
        _default_checkers[BTrees._base._TreeItems] = _iteratorChecker

        for name in ('IF', 'II', 'IO', 'OI', 'OO'):
            for family_name in ('family32', 'family64'):
                family = getattr(BTrees, family_name)
                btree = getattr(family, name).BTree
                # The `_fixup_dictlike` is detected as undefined because it is
                # deleted later on but this function is called beforehand:
                _fixup_dictlike(btree)  # noqa: F821 undefined name

    _fixup_btrees()
    del _fixup_btrees

del _fixup_dictlike


def _fixup_zope_interface():
    # Make sure the provided and implementedBy objects
    # can be iterated.
    # Note that we DO NOT use the _iteratorChecker, but instead
    # we use NoProxy to be sure that the results (of iteration or not) are not
    # proxied. On Python 2, these objects are builtin and don't go through the
    # checking process at all, much like BTrees, so NoProxy is necessary for
    # compatibility. On Python 3, prior to this, iteration was simply not
    # allowed.
    from zope.interface import alsoProvides
    from zope.interface import providedBy

    class I1(Interface):
        pass

    class I2(Interface):
        pass

    @implementer(I1)
    class Obj(object):
        pass

    o = Obj()

    # This will be athe zope.interface.implementedBy from the class
    # a zope.interface.declarations.Implements
    _default_checkers[type(providedBy(o))] = NoProxy

    alsoProvides(o, I2)
    # This will be the zope.interface.Provides from the instance
    _default_checkers[type(providedBy(o))] = NoProxy


_fixup_zope_interface()
del _fixup_zope_interface


def _fixup_itertools():
    # itertools.groupby is a built-in custom iterator type introduced
    # in python2.4. It should have the same checker as other built-in
    # iterators.

    # Also, itertools._grouper also needs to be exposed as an
    # iterator. Its type is not exposed by name, but can be accessed
    # like so: type(list(itertools.groupby([0]))[0][1])

    import itertools

    group = itertools.groupby([0])
    type_group = type(group)
    if type_group not in _default_checkers:
        _default_checkers[type_group] = _iteratorChecker

    type_grouper = type(list(group)[0][1])
    if type_grouper not in _default_checkers:
        _default_checkers[type_grouper] = _iteratorChecker

    # There are also many other custom types in itertools that need the
    # same treatment. See a similar list in
    # test_checker.py:test_itertools_checkers
    def pred(x):
        return x
    iterable = (1, 2, 3)
    pred_iterable = (pred, iterable)
    missing_in_py3 = {'ifilter', 'ifilterfalse', 'imap',
                      'izip', 'izip_longest'}
    missing_in_py2 = {'zip_longest', 'accumulate', 'compress',
                      'combinations', 'combinations_with_replacement'}
    missing = missing_in_py3 if sys.version_info[0] >= 3 else missing_in_py2
    for func, args in (
            ('count', ()),
            ('cycle', ((),)),
            ('dropwhile', pred_iterable),
            ('ifilter', pred_iterable),
            ('ifilterfalse', pred_iterable),
            ('imap', pred_iterable),
            ('islice', (iterable, 2)),
            ('izip', (iterable,)),
            ('izip_longest', (iterable,)),
            ('permutations', (iterable,)),
            ('product', (iterable,)),
            ('repeat', (1, 2)),
            ('starmap', pred_iterable),
            ('takewhile', pred_iterable),
            ('tee', (iterable,)),
            # Python 3 additions
            ('zip_longest', (iterable,)),
            ('accumulate', (iterable,)),
            ('compress', (iterable, ())),
            ('combinations', (iterable, 1)),
            ('combinations_with_replacement', (iterable, 1)),
    ):
        try:
            func = getattr(itertools, func)
        except AttributeError:
            assert func in missing, "Expected %s but not found" % (func,)
            # The following line is hit on PY2, but it doesn't always show:
            continue  # pragma: no cover

        result = func(*args)
        if func == itertools.tee:
            result = result[0]
        tresult = type(result)
        if tresult not in _default_checkers:
            _default_checkers[tresult] = _iteratorChecker


_fixup_itertools()
del _fixup_itertools


def _clear():
    _checkers.clear()
    _checkers.update(_default_checkers)
    _checkers.update(BasicTypes)


_clear()

try:
    from zope.testing.cleanup import addCleanUp
except ImportError:  # pragma: no cover
    pass
else:
    addCleanUp(_clear)
