:mod:`zope.security.proxy`
===============================

.. testsetup::

   from zope.component.testing import setUp
   setUp()

.. autofunction:: zope.security.proxy.getTestProxyItems

.. autofunction:: zope.security.proxy.isinstance

.. doctest::

   >>> from zope.security.proxy import isinstance
   >>> class C1(object):
   ...     pass

   >>> c = C1()
   >>> isinstance(c, C1)
   True

   >>> from zope.security.checker import ProxyFactory
   >>> isinstance(ProxyFactory(c), C1)
   True

   >>> class C2(C1):
   ...     pass

   >>> c = C2()
   >>> isinstance(c, C1)
   True

   >>> from zope.security.checker import ProxyFactory
   >>> isinstance(ProxyFactory(c), C1)
   True



.. testcleanup::

   from zope.component.testing import tearDown
   tearDown()
