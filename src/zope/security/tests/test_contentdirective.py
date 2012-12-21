##############################################################################
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
"""Test 'zope:class' ZCML directive.
"""
import unittest


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

def configfile(s):
    from StringIO import StringIO
    return StringIO("""<configure
      xmlns='http://namespaces.zope.org/zope'
      i18n_domain='zope'>
      %s
      </configure>
      """ % s)

class TestClassDirective(unittest.TestCase):

    def setUp(self):
        from zope.security.tests.exampleclass import ExampleClass
        try:
            del ExampleClass.__implements__
        except AttributeError:
            pass
        try:
            from zope.component.testing import setUp
        except ImportError:
            pass
        else:
            setUp()

    def tearDown(self):
        from zope.security.tests.exampleclass import ExampleClass
        try:
            del ExampleClass.__implements__
        except AttributeError:
            pass
        try:
            from zope.component.testing import tearDown
        except ImportError:
            pass
        else:
            tearDown()

    def _meta(self):
        from zope.configuration.xmlconfig import XMLConfig
        import zope.security
        XMLConfig('meta.zcml', zope.security)()

    @_skip_wo_zope_configuration
    def testEmptyDirective(self):
        from zope.configuration.xmlconfig import xmlconfig
        self._meta()
        f = configfile("""
<class class="zope.security.tests.exampleclass.ExampleClass">
</class>
                       """)
        xmlconfig(f)


    @_skip_wo_zope_configuration
    def testImplements(self):
        from zope.component.interface import queryInterface
        from zope.configuration.xmlconfig import xmlconfig
        from zope.security.tests.exampleclass import ExampleClass
        from zope.security.tests.exampleclass import IExample
        self._meta()
        self.assertEqual(queryInterface(
            "zope.security.tests.exampleclass.IExample"), None)

        f = configfile("""
<class class="zope.security.tests.exampleclass.ExampleClass">
  <implements interface="zope.security.tests.exampleclass.IExample" />
</class>
                       """)
        xmlconfig(f)
        self.failUnless(IExample.implementedBy(ExampleClass))

        self.assertEqual(queryInterface(
            "zope.security.tests.exampleclass.IExample"), IExample)


    @_skip_wo_zope_configuration
    def testMulImplements(self):
        from zope.component.interface import queryInterface
        from zope.configuration.xmlconfig import xmlconfig
        from zope.security.tests.exampleclass import ExampleClass
        from zope.security.tests.exampleclass import IExample
        from zope.security.tests.exampleclass import IExample2
        self._meta()
        self.assertEqual(queryInterface(
            "zope.security.tests.exampleclass.IExample"), None)
        self.assertEqual(queryInterface(
            "zope.security.tests.exampleclass.IExample2"), None)

        f = configfile("""
<class class="zope.security.tests.exampleclass.ExampleClass">
  <implements interface="
           zope.security.tests.exampleclass.IExample
           zope.security.tests.exampleclass.IExample2
                       " />
</class>
                       """)
        xmlconfig(f)
        self.failUnless(IExample.implementedBy(ExampleClass))
        self.failUnless(IExample2.implementedBy(ExampleClass))

        self.assertEqual(queryInterface(
            "zope.security.tests.exampleclass.IExample"), IExample)
        self.assertEqual(queryInterface(
            "zope.security.tests.exampleclass.IExample2"),
                         IExample2)

    @_skip_wo_zope_configuration
    def testRequire(self):
        from zope.configuration.xmlconfig import xmlconfig
        self._meta()
        f = configfile("""
<permission id="zope.View" title="Zope view permission" />
<class class="zope.security.tests.exampleclass.ExampleClass">
    <require permission="zope.View"
                      attributes="anAttribute anotherAttribute" />
</class>
                       """)
        xmlconfig(f)

    @_skip_wo_zope_configuration
    def testAllow(self):
        from zope.configuration.xmlconfig import xmlconfig
        self._meta()
        f = configfile("""
<class class="zope.security.tests.exampleclass.ExampleClass">
    <allow attributes="anAttribute anotherAttribute" />
</class>
                       """)
        xmlconfig(f)

    @_skip_wo_zope_configuration
    def testMimic(self):
        from zope.configuration.xmlconfig import xmlconfig
        self._meta()
        f = configfile("""
<class class="zope.security.tests.exampleclass.ExampleClass">
    <require like_class="zope.security.tests.exampleclass.ExampleClass" />
</class>
                       """)
        xmlconfig(f)


class TestFactorySubdirective(unittest.TestCase):

    def setUp(self):
        try:
            from zope.component.testing import setUp
        except ImportError:
            pass
        else:
            setUp()

    def tearDown(self):
        try:
            from zope.component.testing import tearDown
        except ImportError:
            pass
        else:
            tearDown()

    def _meta(self):
        from zope.configuration.xmlconfig import XMLConfig
        import zope.security
        XMLConfig('meta.zcml', zope.security)()

    @_skip_wo_zope_configuration
    def testFactory(self):
        from zope.component import getUtility
        from zope.component.interfaces import IFactory
        from zope.configuration.xmlconfig import xmlconfig
        self._meta()
        f = configfile("""
<permission id="zope.Foo" title="Zope Foo Permission" />

<class class="zope.security.tests.exampleclass.ExampleClass">
  <factory
      id="test.Example"
      title="Example content"
      description="Example description"
      />
</class>
                       """)
        xmlconfig(f)
        factory = getUtility(IFactory, 'test.Example')
        self.assertEquals(factory.title, "Example content")
        self.assertEquals(factory.description, "Example description")

    @_skip_wo_zope_configuration
    def testFactoryNoId(self):
        from zope.component import getUtility
        from zope.component.interfaces import IFactory
        from zope.component.interfaces import ComponentLookupError
        from zope.configuration.xmlconfig import xmlconfig
        self._meta()
        f = configfile("""
<permission id="zope.Foo" title="Zope Foo Permission" />

<class class="zope.security.tests.exampleclass.ExampleClass">
    <factory
      title="Example content"
      description="Example description"
    />
</class>
                       """)
        xmlconfig(f)
        self.assertRaises(ComponentLookupError, getUtility,
                          IFactory, 'Example')
        factory = getUtility(
            IFactory, 'zope.security.tests.exampleclass.ExampleClass')
        self.assertEquals(factory.title, "Example content")
        self.assertEquals(factory.description, "Example description")


    @_skip_wo_zope_configuration
    def testFactoryPublicPermission(self):
        from zope.component import getUtility
        from zope.component.interfaces import IFactory
        from zope.configuration.xmlconfig import xmlconfig
        self._meta()
        f = configfile("""
<class class="zope.security.tests.exampleclass.ExampleClass">
    <factory
      id="test.Example"
      title="Example content"
      description="Example description"
    />
</class>
            """)
        xmlconfig(f)
        factory = getUtility(IFactory, 'test.Example')
        self.assert_(hasattr(factory, '__Security_checker__'))


def test_suite():

    return unittest.TestSuite((
        unittest.makeSuite(TestClassDirective),
        unittest.makeSuite(TestFactorySubdirective),
    ))
