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
"""Directives Tests
"""
import unittest


def pprint(ob, width=70):
    from pprint import PrettyPrinter
    PrettyPrinter(width=width).pprint(ob)

TEST_PERM = 'zope.security.metaconfigure.test'
TEST_BAD_PERM = 'zope.security.metaconfigure.bad'

def test_protectModule():
    """
    >>> from zope.security import metaconfigure

    >>> from zope.security.tests import test_directives
    >>> from zope.security.interfaces import IPermission
    >>> from zope.security.permission import Permission

    >>> from zope.component import provideUtility

    Initially, there's no checker defined for the module:

    >>> from zope.security.checker import moduleChecker
    >>> moduleChecker(test_directives)
        
    >>> perm = Permission(TEST_PERM, '')
    >>> provideUtility(perm, IPermission, TEST_PERM)
    >>> metaconfigure.protectModule(test_directives, 'foo', TEST_PERM)

    Now, the checker should exist and have an access dictionary with the
    name and permission:

    >>> checker = moduleChecker(test_directives)
    >>> cdict = checker.get_permissions
    >>> pprint(cdict)
    {'foo': 'zope.security.metaconfigure.test'}
    
    If we define additional names, they will be added to the dict:

    >>> metaconfigure.protectModule(test_directives, 'bar', TEST_PERM)
    >>> metaconfigure.protectModule(test_directives, 'baz', TEST_PERM)
    >>> pprint(cdict)
    {'bar': 'zope.security.metaconfigure.test',
     'baz': 'zope.security.metaconfigure.test',
     'foo': 'zope.security.metaconfigure.test'}
        
    """

def test_allow():
    """

    The allow directive creates actions for each named defined
    directly, or via interface:

    >>> from zope.interface import Interface
    >>> from zope.interface import Attribute
    >>> from zope.security import metaconfigure

    >>> class I1(Interface):
    ...     def x(): pass
    ...     y = Attribute("Y")
    >>> class I2(I1):
    ...     def a(): pass
    ...     b = Attribute("B")
    >>> class Context(object):
    ...     def __init__(self):
    ...         self.actions = []
    ...
    ...     def action(self, discriminator, callable, args):
    ...         self.actions.append(
    ...             {'discriminator': discriminator,
    ...              'callable': int(callable is metaconfigure.protectModule),
    ...              'args': args})
    ...
    ...     module='testmodule'

    >>> context = Context()
    >>> metaconfigure.allow(context, attributes=['foo', 'bar'],
    ...                     interface=[I1, I2])

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

    """

def test_require():
    """

    The allow directive creates actions for each named defined
    directly, or via interface:

    >>> from zope.interface import Interface
    >>> from zope.interface import Attribute
    >>> from zope.security import metaconfigure

    >>> class I1(Interface):
    ...     def x(): pass
    ...     y = Attribute("Y")
    >>> class I2(I1):
    ...     def a(): pass
    ...     b = Attribute("B")
    >>> class Context(object):
    ...     def __init__(self):
    ...         self.actions = []
    ...
    ...     def action(self, discriminator, callable, args):
    ...         self.actions.append(
    ...             {'discriminator': discriminator,
    ...              'callable': int(callable is metaconfigure.protectModule),
    ...              'args': args})
    ...
    ...     module='testmodule'

    >>> context = Context()
    >>> metaconfigure.require(context, attributes=['foo', 'bar'],
    ...                       interface=[I1, I2], permission='p')

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
    
    """


def _skip_wo_zope_configuration(testfunc):
    try:
        import zope.configuration.xmlconfig
    except ImportError:
        from functools import update_wrapper
        def dummy(self):
            pass
        update_wrapper(dummy, testfunc)
        return dummy
    else:
        return testfunc


@_skip_wo_zope_configuration
def make_dummy():
    from zope.interface import Interface
    import zope.security.zcml
    global IDummy
    class IDummy(Interface):
        perm = zope.security.zcml.Permission(title=u'')


perms = []

def dummy(context_, perm):
    global perms
    perms.append(perm)


class DirectivesTest(unittest.TestCase):

    def setUp(self):
        try:
            from zope.component.testing import setUp
        except ImportError:
            pass
        else:
            setUp()

    def tearDown(self):
        del perms[:]
        try:
            from zope.component.testing import tearDown
        except ImportError:
            pass
        else:
            tearDown()

    @_skip_wo_zope_configuration
    def testRedefinePermission(self):
        from zope.configuration import xmlconfig
        from zope.security import tests
        make_dummy()
        xmlconfig.file("redefineperms.zcml", tests)
        self.assertEqual(perms, ['zope.Security'])

def test_suite():
    import doctest
    from zope.component.testing import tearDown
    from zope.component.testing import setUp

    return unittest.TestSuite((
        doctest.DocTestSuite(setUp=setUp, tearDown=tearDown),
        doctest.DocTestSuite('zope.security.zcml'),
        unittest.makeSuite(DirectivesTest),
    ))
