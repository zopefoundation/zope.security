:mod:`zope.security.checker`
============================

.. automodule:: zope.security.checker
   :members:
   :member-order: bysource


Protections for Modules
-----------------------

The :func:`zope.secuirty.checker.moduleChecker` API can be used to
determine whether a module has been protected: Initially, there's no checker
defined for the module:

.. doctest::

   >>> from zope.security.checker import moduleChecker
   >>> from zope.security.tests import test_directives
   >>> moduleChecker(test_directives) is None
   True

We can add a checker using :func:`zope.security.metaconfigure.protectModule`:

.. doctest::

   >>> from zope.component import provideUtility
   >>> from zope.security.metaconfigure import protectModule
   >>> from zope.security.permission import Permission
   >>> from zope.security.interfaces import IPermission
   >>> TEST_PERM = 'zope.security.metaconfigure.test'
   >>> perm = Permission(TEST_PERM, '')
   >>> provideUtility(perm, IPermission, TEST_PERM)
   >>> protectModule(test_directives, 'foo', TEST_PERM)

Now, the checker should exist and have an access dictionary with the
name and permission:

.. doctest::

   >>> def pprint(ob, width=70):
   ...     from pprint import PrettyPrinter
   ...     PrettyPrinter(width=width).pprint(ob)
   >>> checker = moduleChecker(test_directives)
   >>> cdict = checker.get_permissions
   >>> pprint(cdict)
   {'foo': 'zope.security.metaconfigure.test'}
   
   If we define additional names, they will be added to the dict:

   >>> protectModule(test_directives, 'bar', TEST_PERM)
   >>> protectModule(test_directives, 'baz', TEST_PERM)
   >>> pprint(cdict)
   {'bar': 'zope.security.metaconfigure.test',
    'baz': 'zope.security.metaconfigure.test',
    'foo': 'zope.security.metaconfigure.test'}
        
The allow directive creates actions for each named defined
directly, or via interface:

.. doctest::

   >>> from zope.interface import Interface
   >>> from zope.interface import Attribute
   >>> from zope.security.metaconfigure import allow
   >>> class I1(Interface):
   ...     def x(): pass
   ...     y = Attribute("Y")
   >>> class I2(I1):
   ...     def a(): pass
   ...     b = Attribute("B")
   >>> class AContext(object):
   ...     def __init__(self):
   ...         self.actions = []
   ...
   ...     def action(self, discriminator, callable, args):
   ...         self.actions.append(
   ...             {'discriminator': discriminator,
   ...              'callable': int(callable is protectModule),
   ...              'args': args})
   ...     module='testmodule'

   >>> context = AContext()
   >>> allow(context, attributes=['foo', 'bar'], interface=[I1, I2])
   >>> context.actions.sort(
   ...    lambda a, b: cmp(a['discriminator'], b['discriminator']))
   >>> pprint(context.actions)
   [{'args': ('testmodule', 'a', 'zope.Public'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'a')},
    {'args': ('testmodule', 'b', 'zope.Public'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'b')},
    {'args': ('testmodule', 'bar', 'zope.Public'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'bar')},
    {'args': ('testmodule', 'foo', 'zope.Public'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'foo')},
    {'args': ('testmodule', 'x', 'zope.Public'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'x')},
    {'args': ('testmodule', 'y', 'zope.Public'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'y')}]

The provide directive creates actions for each named defined
directly, or via interface:

.. doctest::

   >>> from zope.security.metaconfigure import require
   >>> class RContext(object):
   ...     def __init__(self):
   ...         self.actions = []
   ...     def action(self, discriminator, callable, args):
   ...         self.actions.append(
   ...             {'discriminator': discriminator,
   ...              'callable': int(callable is protectModule),
   ...              'args': args})
   ...     module='testmodule'

   >>> context = RContext()
   >>> require(context, attributes=['foo', 'bar'],
   ...         interface=[I1, I2], permission='p')

   >>> context.actions.sort(
   ...    lambda a, b: cmp(a['discriminator'], b['discriminator']))
   >>> pprint(context.actions)
   [{'args': ('testmodule', 'a', 'p'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'a')},
    {'args': ('testmodule', 'b', 'p'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'b')},
    {'args': ('testmodule', 'bar', 'p'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'bar')},
    {'args': ('testmodule', 'foo', 'p'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'foo')},
    {'args': ('testmodule', 'x', 'p'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'x')},
    {'args': ('testmodule', 'y', 'p'),
     'callable': 1,
     'discriminator': ('http://namespaces.zope.org/zope:module',
                       'testmodule',
                       'y')}]


Protections for set objects
---------------------------

we can do everything we expect to be able to do with proxied sets.

.. doctest::

   >>> def check_forbidden_get(object, attr):
   ...     from zope.security.interfaces import ForbiddenAttribute
   ...     try:
   ...         return getattr(object, attr)
   ...     except ForbiddenAttribute, e:
   ...         return 'ForbiddenAttribute: %s' % e[0]
   >>> from zope.security.checker import ProxyFactory
   >>> from zope.security.interfaces import ForbiddenAttribute
   >>> us = set((1, 2))
   >>> s = ProxyFactory(us)

   >>> check_forbidden_get(s, 'add') # Verify that we are protected
   'ForbiddenAttribute: add'
   >>> check_forbidden_get(s, 'remove') # Verify that we are protected
   'ForbiddenAttribute: remove'
   >>> check_forbidden_get(s, 'discard') # Verify that we are protected
   'ForbiddenAttribute: discard'
   >>> check_forbidden_get(s, 'pop') # Verify that we are protected
   'ForbiddenAttribute: pop'
   >>> check_forbidden_get(s, 'clear') # Verify that we are protected
   'ForbiddenAttribute: clear'

   >>> len(s)
   2

   >>> 1 in s
   True

   >>> 1 not in s
   False

   >>> s.issubset(set((1,2,3)))
   True

   >>> s.issuperset(set((1,2,3)))
   False

   >>> c = s.union(set((2, 3)))
   >>> sorted(c)
   [1, 2, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s | set((2, 3))
   >>> sorted(c)
   [1, 2, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s | ProxyFactory(set((2, 3)))
   >>> sorted(c)
   [1, 2, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = set((2, 3)) | s
   >>> sorted(c)
   [1, 2, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s.intersection(set((2, 3)))
   >>> sorted(c)
   [2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s & set((2, 3))
   >>> sorted(c)
   [2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s & ProxyFactory(set((2, 3)))
   >>> sorted(c)
   [2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = set((2, 3)) & s
   >>> sorted(c)
   [2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s.difference(set((2, 3)))
   >>> sorted(c)
   [1]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s - ProxyFactory(set((2, 3)))
   >>> sorted(c)
   [1]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s - set((2, 3))
   >>> sorted(c)
   [1]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = set((2, 3)) - s
   >>> sorted(c)
   [3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s.symmetric_difference(set((2, 3)))
   >>> sorted(c)
   [1, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s ^ set((2, 3))
   >>> sorted(c)
   [1, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s ^ ProxyFactory(set((2, 3)))
   >>> sorted(c)
   [1, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = set((2, 3)) ^ s
   >>> sorted(c)
   [1, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s.copy()
   >>> sorted(c)
   [1, 2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> str(s) == str(us)
   True
   
   >>> repr(s) == repr(us)
   True

   Always available:

   >>> s < us
   False
   >>> s > us
   False
   >>> s <= us
   True
   >>> s >= us
   True
   >>> s == us
   True
   >>> s != us
   False

Note that you can't compare proxied sets with other proxied sets
due a limitaion in the set comparison functions which won't work
with any kind of proxy.
   
.. doctest::

   >>> bool(s)
   True
   >>> s.__class__ == set
   True

Likewise with proxied frozensets.

.. doctest::

   >>> def check_forbidden_get(object, attr):
   ...     from zope.security.interfaces import ForbiddenAttribute
   ...     try:
   ...         return getattr(object, attr)
   ...     except ForbiddenAttribute, e:
   ...         return 'ForbiddenAttribute: %s' % e[0]
   >>> from zope.security.checker import ProxyFactory
   >>> from zope.security.interfaces import ForbiddenAttribute
   >>> us = frozenset((1, 2))
   >>> s = ProxyFactory(us)

   >>> check_forbidden_get(s, 'add') # Verify that we are protected
   'ForbiddenAttribute: add'
   >>> check_forbidden_get(s, 'remove') # Verify that we are protected
   'ForbiddenAttribute: remove'
   >>> check_forbidden_get(s, 'discard') # Verify that we are protected
   'ForbiddenAttribute: discard'
   >>> check_forbidden_get(s, 'pop') # Verify that we are protected
   'ForbiddenAttribute: pop'
   >>> check_forbidden_get(s, 'clear') # Verify that we are protected
   'ForbiddenAttribute: clear'

   >>> len(s)
   2

   >>> 1 in s
   True

   >>> 1 not in s
   False

   >>> s.issubset(frozenset((1,2,3)))
   True

   >>> s.issuperset(frozenset((1,2,3)))
   False

   >>> c = s.union(frozenset((2, 3)))
   >>> sorted(c)
   [1, 2, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s | frozenset((2, 3))
   >>> sorted(c)
   [1, 2, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s | ProxyFactory(frozenset((2, 3)))
   >>> sorted(c)
   [1, 2, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = frozenset((2, 3)) | s
   >>> sorted(c)
   [1, 2, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s.intersection(frozenset((2, 3)))
   >>> sorted(c)
   [2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s & frozenset((2, 3))
   >>> sorted(c)
   [2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s & ProxyFactory(frozenset((2, 3)))
   >>> sorted(c)
   [2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = frozenset((2, 3)) & s
   >>> sorted(c)
   [2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s.difference(frozenset((2, 3)))
   >>> sorted(c)
   [1]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s - ProxyFactory(frozenset((2, 3)))
   >>> sorted(c)
   [1]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s - frozenset((2, 3))
   >>> sorted(c)
   [1]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = frozenset((2, 3)) - s
   >>> sorted(c)
   [3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s.symmetric_difference(frozenset((2, 3)))
   >>> sorted(c)
   [1, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s ^ frozenset((2, 3))
   >>> sorted(c)
   [1, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s ^ ProxyFactory(frozenset((2, 3)))
   >>> sorted(c)
   [1, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = frozenset((2, 3)) ^ s
   >>> sorted(c)
   [1, 3]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> c = s.copy()
   >>> sorted(c)
   [1, 2]
   >>> check_forbidden_get(c, 'add')
   'ForbiddenAttribute: add'

   >>> str(s) == str(us)
   True
   
   >>> repr(s) == repr(us)
   True

   Always available:

   >>> s < us
   False
   >>> s > us
   False
   >>> s <= us
   True
   >>> s >= us
   True
   >>> s == us
   True
   >>> s != us
   False

Note that you can't compare proxied sets with other proxied sets
due a limitaion in the frozenset comparison functions which won't work
with any kind of proxy.
   
.. doctest::

   >>> bool(s)
   True
   >>> s.__class__ == frozenset
   True
