:mod:`zope.security.zcml`
===============================

Configuring security via ZCML
-----------------------------

:mod:`zope.security` provides a ZCML file that configures some utilities and
a couple of permissions:

.. doctest::

  >>> from zope.component import getGlobalSiteManager
  >>> from zope.configuration.xmlconfig import XMLConfig
  >>> from zope.component.testing import setUp
  >>> import zope.security
  >>> setUp()  # clear global component registry
  >>> XMLConfig('permissions.zcml', zope.security)()

  >>> len(list(getGlobalSiteManager().registeredUtilities()))
  7

Clear the current state:

.. doctest::

  >>> from zope.component.testing import setUp, tearDown
  >>> tearDown()
  >>> setUp()

  >>> XMLConfig('configure.zcml', zope.security)()

  >>> len(list(getGlobalSiteManager().registeredUtilities()))
  10

.. autoclass:: zope.security.zcml.Permission
   :members:
   :member-order: bysource

Let's look at an example:

.. doctest::

   >>> from zope.security.zcml import Permission
   >>> class FauxContext(object):
   ...     permission_mapping = {'zope.ManageCode':'zope.private'}
   ...     _actions = []
   ...     def action(self, **kws):
   ...        self._actions.append(kws)
   >>> context = FauxContext()
   >>> field = Permission().bind(context)

Let's test the fromUnicode method:

.. doctest::

   >>> field.fromUnicode(u'zope.foo')
   'zope.foo'
   >>> field.fromUnicode(u'zope.ManageCode')
   'zope.private'

Now let's see whether validation works alright

.. doctest::

   >>> field._validate('zope.ManageCode')
   >>> context._actions[0]['args']
   (None, 'zope.foo')

   >>> from zope.schema.interfaces import InvalidId
   >>> try:
   ...     field._validate('3 foo')
   ... except InvalidId as e:
   ...     e
   InvalidId('3 foo')

   zope.Public is always valid
   >>> field._validate('zope.Public')


.. autointerface:: zope.security.zcml.ISecurityPolicyDirective
   :members:
   :member-order: bysource

.. autofunction:: zope.security.zcml.securityPolicy

.. autointerface:: zope.security.zcml.IPermissionDirective
   :members:
   :member-order: bysource

.. autofunction:: zope.security.zcml.permission

.. autointerface:: zope.security.zcml.IRedefinePermission
   :members:
   :member-order: bysource

.. autofunction:: zope.security.zcml.redefinePermission
