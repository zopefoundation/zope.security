=====================
 zope.security.proxy
=====================

.. currentmodule:: zope.security.proxy

An introduction to proxies and their uses can be found in :doc:`../proxy`.

.. seealso:: :ref:`proxy-known-issues`

.. testsetup::

   from zope.component.testing import setUp
   setUp()

.. autofunction:: getChecker

.. autofunction:: removeSecurityProxy

.. autofunction:: getTestProxyItems

.. autofunction:: isinstance

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

.. autoclass:: Proxy

.. autoclass:: ProxyPy

.. testcleanup::

   from zope.component.testing import tearDown
   tearDown()
