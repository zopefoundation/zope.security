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
   >>> from zope.security.tests import test_zcml_functest
   >>> moduleChecker(test_zcml_functest) is None
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
   >>> protectModule(test_zcml_functest, 'foo', TEST_PERM)

Now, the checker should exist and have an access dictionary with the
name and permission:

.. doctest::

   >>> def pprint(ob, width=70):
   ...     from pprint import PrettyPrinter
   ...     PrettyPrinter(width=width).pprint(ob)
   >>> checker = moduleChecker(test_zcml_functest)
   >>> cdict = checker.get_permissions
   >>> pprint(cdict)
   {'foo': 'zope.security.metaconfigure.test'}
   
   If we define additional names, they will be added to the dict:

   >>> protectModule(test_zcml_functest, 'bar', TEST_PERM)
   >>> protectModule(test_zcml_functest, 'baz', TEST_PERM)
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
   >>> context.actions.sort(key=lambda a: a['discriminator'])
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

   >>> context.actions.sort(key=lambda a: a['discriminator'])
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


Protections for standard objects
--------------------------------

.. doctest::

   >>> from zope.security.checker import ProxyFactory
   >>> from zope.security.interfaces import ForbiddenAttribute
   >>> def check_forbidden_get(object, attr):
   ...     from zope.security.interfaces import ForbiddenAttribute
   ...     try:
   ...         return getattr(object, attr)
   ...     except ForbiddenAttribute as e:
   ...         return 'ForbiddenAttribute: %s' % e.args[0]
   >>> def check_forbidden_setitem(object, item, value):
   ...     from zope.security.interfaces import ForbiddenAttribute
   ...     try:
   ...         object[item] = value
   ...     except ForbiddenAttribute as e:
   ...         return 'ForbiddenAttribute: %s' % e.args[0]
   >>> def check_forbidden_delitem(object, item):
   ...     from zope.security.interfaces import ForbiddenAttribute
   ...     try:
   ...         del object[item]
   ...     except ForbiddenAttribute as e:
   ...         return 'ForbiddenAttribute: %s' % e.args[0]
   >>> def check_forbidden_call(callable, *args): # **
   ...     from zope.security.interfaces import ForbiddenAttribute
   ...     try:
   ...         return callable(*args) # **
   ...     except ForbiddenAttribute as e:
   ...         return 'ForbiddenAttribute: %s' % e.args[0]

Rocks
#####

Rocks are immuatle, non-callable objects without interesting methods.  They
*don't* get proxied.

.. doctest::

   >>> int(type(ProxyFactory(  object()  )) is object)
   1
   >>> int(type(ProxyFactory(  1  )) is int)
   1
   >>> int(type(ProxyFactory(  1.0  )) is float)
   1
   >>> int(type(ProxyFactory(  1j  )) is complex)
   1
   >>> int(type(ProxyFactory(  None  )) is type(None))
   1
   >>> int(type(ProxyFactory(  'xxx'  )) is str)
   1
   >>> int(type(ProxyFactory(  True  )) is type(True))
   1

Datetime-reltatd instances are rocks, too:

.. doctest::

   >>> from datetime import timedelta, datetime, date, time, tzinfo
   >>> int(type(ProxyFactory(  timedelta(1)  )) is timedelta)
   1
   >>> int(type(ProxyFactory(  datetime(2000, 1, 1)  )) is datetime)
   1
   >>> int(type(ProxyFactory(  date(2000, 1, 1)  )) is date)
   1
   >>> int(type(ProxyFactory(  time()  )) is time)
   1
   >>> int(type(ProxyFactory(  tzinfo() )) is tzinfo)
   1
   >>> try:
   ...     from pytz import UTC
   ... except ImportError:  # pytz checker only if pytz is present.
   ...     1
   ... else:
   ...      int(type(ProxyFactory(  UTC )) is type(UTC))
   1


dicts
#####

We can do everything we expect to be able to do with proxied dicts.

.. doctest::

   >>> d = ProxyFactory({'a': 1, 'b': 2})
   >>> check_forbidden_get(d, 'clear') # Verify that we are protected
   'ForbiddenAttribute: clear'
   >>> check_forbidden_setitem(d, 3, 4) # Verify that we are protected
   'ForbiddenAttribute: __setitem__'
   >>> d['a']
   1
   >>> len(d)
   2
   >>> sorted(list(d))
   ['a', 'b']
   >>> d.get('a')
   1
   >>> int('a' in d)
   1
   >>> c = d.copy()
   >>> check_forbidden_get(c, 'clear')
   'ForbiddenAttribute: clear'
   >>> int(str(c) in ("{'a': 1, 'b': 2}", "{'b': 2, 'a': 1}"))
   1
   >>> int(repr(c) in ("{'a': 1, 'b': 2}", "{'b': 2, 'a': 1}"))
   1
   >>> def sorted(x):
   ...    x = list(x)
   ...    x.sort()
   ...    return x
   >>> sorted(d.keys())
   ['a', 'b']
   >>> sorted(d.values())
   [1, 2]
   >>> sorted(d.items())
   [('a', 1), ('b', 2)]

Always available (note, that dicts in python-3.x are not orderable, so we are
not checking that under python > 2):

.. doctest::

    >>> int(d != d)
    0
    >>> int(bool(d))
    1
    >>> int(d.__class__ == dict)
    1

lists
#####

We can do everything we expect to be able to do with proxied lists.

.. doctest::

   >>> l = ProxyFactory([1, 2])
   >>> check_forbidden_delitem(l, 0)
   'ForbiddenAttribute: __delitem__'
   >>> check_forbidden_setitem(l, 0, 3)
   'ForbiddenAttribute: __setitem__'
   >>> l[0]
   1
   >>> l[0:1]
   [1]
   >>> check_forbidden_setitem(l[:1], 0, 2)
   'ForbiddenAttribute: __setitem__'
   >>> len(l)
   2
   >>> tuple(l)
   (1, 2)
   >>> int(1 in l)
   1
   >>> l.index(2)
   1
   >>> l.count(2)
   1
   >>> str(l)
   '[1, 2]'
   >>> repr(l)
   '[1, 2]'
   >>> l + l
   [1, 2, 1, 2]

Always available:

.. doctest::

   >>> int(l < l)
   0
   >>> int(l > l)
   0
   >>> int(l <= l)
   1
   >>> int(l >= l)
   1
   >>> int(l == l)
   1
   >>> int(l != l)
   0
   >>> int(bool(l))
   1
   >>> int(l.__class__ == list)
   1

tuples
######

We can do everything we expect to be able to do with proxied tuples.

.. doctest::

   >>> from zope.security.checker import ProxyFactory
   >>> l = ProxyFactory((1, 2))
   >>> l[0]
   1
   >>> l[0:1]
   (1,)
   >>> len(l)
   2
   >>> list(l)
   [1, 2]
   >>> int(1 in l)
   1
   >>> str(l)
   '(1, 2)'
   >>> repr(l)
   '(1, 2)'
   >>> l + l
   (1, 2, 1, 2)

Always available:

.. doctest::

   >>> int(l < l)
   0
   >>> int(l > l)
   0
   >>> int(l <= l)
   1
   >>> int(l >= l)
   1
   >>> int(l == l)
   1
   >>> int(l != l)
   0
   >>> int(bool(l))
   1
   >>> int(l.__class__ == tuple)
   1

sets
####

we can do everything we expect to be able to do with proxied sets.

.. doctest::

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



frozensets
##########

we can do everything we expect to be able to do with proxied frozensets.

.. doctest::

   >>> def check_forbidden_get(object, attr):
   ...     from zope.security.interfaces import ForbiddenAttribute
   ...     try:
   ...         return getattr(object, attr)
   ...     except ForbiddenAttribute as e:
   ...         return 'ForbiddenAttribute: %s' % e.args[0]
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

iterators
#########

.. doctest::

   >>> [a for a in ProxyFactory(iter([1, 2]))]
   [1, 2]
   >>> list(ProxyFactory(iter([1, 2])))
   [1, 2]
   >>> list(ProxyFactory(iter((1, 2))))
   [1, 2]
   >>> list(ProxyFactory(iter({1:1, 2:2})))
   [1, 2]
   >>> def f():
   ...     for i in 1, 2:
   ...             yield i
   ...
   >>> list(ProxyFactory(f()))
   [1, 2]
   >>> list(ProxyFactory(f)())
   [1, 2]


We can iterate over custom sequences, too:

.. doctest::

   >>> class X(object):
   ...   d = 1, 2, 3
   ...   def __getitem__(self, i):
   ...      return self.d[i]
   ...
   >>> x = X()

We can iterate over sequences

.. doctest::

   >>> list(x)
   [1, 2, 3]

   >>> from zope.security.checker import NamesChecker
   >>> from zope.security.checker import ProxyFactory
   >>> c = NamesChecker(['__getitem__', '__len__'])
   >>> p = ProxyFactory(x, c)

Even if they are proxied

.. doctest::

   >>> list(p)
   [1, 2, 3]

But if the class has an iter:

.. doctest::

   >>> X.__iter__ = lambda self: iter(self.d)
   >>> list(x)
   [1, 2, 3]

We shouldn't be able to iterate if we don't have an assertion:

.. doctest::

   >>> check_forbidden_call(list, p)
   'ForbiddenAttribute: __iter__'


New-style classes
#################

.. doctest::

   >>> from zope.security.checker import NamesChecker
   >>> class C(object):
   ...    x = 1
   ...    y = 2
   >>> C = ProxyFactory(C)
   >>> check_forbidden_call(C)
   'ForbiddenAttribute: __call__'
   >>> check_forbidden_get(C, '__dict__')
   'ForbiddenAttribute: __dict__'
   >>> s = str(C)
   >>> s = repr(C)
   >>> int(C.__module__ == __name__)
   1
   >>> len(C.__bases__)
   1
   >>> len(C.__mro__)
   2

Always available:

.. doctest::

   >>> int(C == C)
   1
   >>> int(C != C)
   0
   >>> int(bool(C))
   1
   >>> int(C.__class__ == type)
   1

New-style Instances
###################

.. doctest::

   >>> class C(object):
   ...    x = 1
   ...    y = 2
   >>> c = ProxyFactory(C(), NamesChecker(['x']))
   >>> check_forbidden_get(c, 'y')
   'ForbiddenAttribute: y'
   >>> check_forbidden_get(c, 'z')
   'ForbiddenAttribute: z'
   >>> c.x
   1
   >>> int(c.__class__ == C)
   1

Always available:

.. doctest::

   >>> int(c == c)
   1
   >>> int(c != c)
   0
   >>> int(bool(c))
   1
   >>> int(c.__class__ == C)
   1


Classic Classes
###############

.. doctest::

   >>> class C:
   ...    x = 1
   >>> C = ProxyFactory(C)
   >>> check_forbidden_call(C)
   'ForbiddenAttribute: __call__'
   >>> check_forbidden_get(C, '__dict__')
   'ForbiddenAttribute: __dict__'
   >>> s = str(C)
   >>> s = repr(C)
   >>> int(C.__module__ == __name__)
   1
   >>> len(C.__bases__)
   1

Always available:

.. doctest::

   >>> int(C == C)
   1
   >>> int(C != C)
   0
   >>> int(bool(C))
   1

Classic Instances
#################

.. doctest::

   >>> class C(object):
   ...    x, y = 1, 2
   >>> c = ProxyFactory(C(), NamesChecker(['x']))
   >>> check_forbidden_get(c, 'y')
   'ForbiddenAttribute: y'
   >>> check_forbidden_get(c, 'z')
   'ForbiddenAttribute: z'
   >>> c.x
   1
   >>> int(c.__class__ == C)
   1

Always available:

.. doctest::

   >>> int(c == c)
   1
   >>> int(c != c)
   0
   >>> int(bool(c))
   1
   >>> int(c.__class__ == C)
   1

Interfaces and declarations
###########################

We can still use interfaces though proxies:

.. doctest::

   >>> from zope.interface import directlyProvides
   >>> from zope.interface import implementer
   >>> from zope.interface import provider
   >>> class I(Interface):
   ...     pass
   >>> class IN(Interface):
   ...     pass
   >>> class II(Interface):
   ...     pass
   >>> @implementer(I)
   ... @provider(IN)
   ... class N(object):
   ...     pass
   >>> n = N()
   >>> directlyProvides(n, II)
   >>> N = ProxyFactory(N)
   >>> n = ProxyFactory(n)
   >>> I.implementedBy(N)
   True
   >>> IN.providedBy(N)
   True
   >>> I.providedBy(n)
   True
   >>> II.providedBy(n)
   True


abstract Base Classes
#####################

We work with the ABCMeta meta class:

.. doctest::

   >>> import abc
   >>> class MyABC:
   ...     __metaclass__ = abc.ABCMeta
   >>> class Foo(MyABC): pass
   >>> class Bar(Foo): pass
   >>> PBar = ProxyFactory(Bar)
   >>> [c.__name__ for c in PBar.__mro__]
   ['Bar', 'Foo', 'MyABC', 'object']
   >>> check_forbidden_call(PBar)
   'ForbiddenAttribute: __call__'
   >>> check_forbidden_get(PBar, '__dict__')
   'ForbiddenAttribute: __dict__'
   >>> s = str(PBar)
   >>> s = repr(PBar)
   >>> int(PBar.__module__ == __name__)
   1
   >>> len(PBar.__bases__)
   1

Always available:

.. doctest::

   >>> int(PBar == PBar)
   1
   >>> int(PBar != PBar)
   0
   >>> int(bool(PBar))
   1
   >>> int(PBar.__class__ == type)
   1
