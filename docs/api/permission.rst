==========================
 zope.security.permission
==========================

.. currentmodule:: zope.security.permission

.. testsetup::

   from zope.component.testing import setUp
   setUp()

.. autoclass:: zope.security.permission.Permission
   :members:
   :member-order: bysource


.. autofunction:: zope.security.permission.checkPermission

.. doctest::

   >>> from zope.security.permission import checkPermission
   >>> from zope.component import provideUtility
   >>> from zope.security.interfaces import IPermission
   >>> from zope.security.permission import Permission
   >>> x = Permission('x')
   >>> provideUtility(x, IPermission, 'x')

   >>> checkPermission(None, 'x')
   >>> checkPermission(None, 'y')
   Traceback (most recent call last):
   ...
   ValueError: ('Undefined permission ID', 'y')

The :data:`zope.security.checker.CheckerPublic` permission always exists:

.. doctest::

   >>> from zope.security.checker import CheckerPublic
   >>> checkPermission(None, CheckerPublic)


.. autofunction:: zope.security.permission.allPermissions

.. doctest::

   >>> from zope.security.permission import allPermissions
   >>> from zope.component import provideUtility
   >>> y = Permission('y')
   >>> provideUtility(y, IPermission, 'y')

   >>> ids = sorted(allPermissions(None))
   >>> for perm in sorted(allPermissions(None)):
   ...     print(perm)
   x
   y


.. autofunction:: zope.security.permission.PermissionsVocabulary

To illustrate, we need to register the permissions vocabulary:

.. doctest::

   >>> from zope.security.permission import PermissionsVocabulary
   >>> from zope.schema.vocabulary import _clear
   >>> _clear()

   >>> from zope.schema.vocabulary import getVocabularyRegistry
   >>> registry = getVocabularyRegistry()
   >>> registry.register('Permissions', PermissionsVocabulary)

We can now lookup the permissions we created earlier using the vocabulary:

.. doctest::

   >>> vocab = registry.get(None, 'Permissions')
   >>> vocab.getTermByToken('x').value is x
   True
   >>> vocab.getTermByToken('y').value is y
   True


.. autofunction:: zope.security.permission.PermissionIdsVocabulary

To illustrate, we need to register the permission IDs vocabulary:

.. doctest::

   >>> from zope.security.permission import PermissionIdsVocabulary
   >>> registry.register('Permission Ids', PermissionIdsVocabulary)

   We also need to register the special 'zope.Public' permission:

   >>> provideUtility(Permission('zope.Public'), IPermission, 'zope.Public')

We can now lookup these permissions using the vocabulary:

.. doctest::

   >>> vocab = registry.get(None, 'Permission Ids')

The non-public permissions 'x' and 'y' are string values:

.. doctest::

   >>> print(vocab.getTermByToken('x').value)
   x
   >>> print(vocab.getTermByToken('y').value)
   y

However, the public permission value is :data:`~.CheckerPublic`:

.. doctest::

   >>> vocab.getTermByToken('zope.Public').value is CheckerPublic
   True

and its title is shortened:

.. doctest::

   >>> print(vocab.getTermByToken('zope.Public').title)
   Public

The terms are sorted by title except for the public permission, which is
listed first:

.. doctest::

   >>> for term in vocab:
   ...    print(term.title)
   Public
   x
   y


.. testcleanup::

   from zope.component.testing import tearDown
   tearDown()
