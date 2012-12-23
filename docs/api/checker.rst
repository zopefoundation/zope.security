:mod:`zope.security.checker`
============================

.. automodule:: zope.security.checker
   :members:
   :member-order: bysource

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
