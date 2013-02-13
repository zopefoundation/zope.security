##############################################################################
#
# Copyright (c) 2001, 2002, 2003, 2012 Zope Foundation and Contributors.
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
    from zope.security._compat import StringIO
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
        self.assertTrue(IExample.implementedBy(ExampleClass))

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
        self.assertTrue(IExample.implementedBy(ExampleClass))
        self.assertTrue(IExample2.implementedBy(ExampleClass))

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
        self.assertEqual(factory.title, "Example content")
        self.assertEqual(factory.description, "Example description")

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
        self.assertEqual(factory.title, "Example content")
        self.assertEqual(factory.description, "Example description")


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
        self.assertTrue(hasattr(factory, '__Security_checker__'))


class Context(object):
    actions = ()

    def action(self, discriminator, callable, args):
        self.actions += ((discriminator, callable, args), )

    def __repr__(self):
        from zope.security._compat import StringIO
        import re
        import pprint
        atre = re.compile(' at [0-9a-fA-Fx]+')
        stream = StringIO()
        pprinter = pprint.PrettyPrinter(stream=stream, width=60)
        pprinter.pprint(self.actions)
        r = stream.getvalue()
        return (''.join(atre.split(r))).strip()


template = """<configure
   xmlns='http://namespaces.zope.org/zope'
   xmlns:test='http://www.zope.org/NS/Zope3/test'
   i18n_domain='zope'>
   %s
   </configure>"""


class TestFactoryDirective(unittest.TestCase):

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

    def meta(self):
        import zope.security
        from zope.configuration.xmlconfig import XMLConfig
        XMLConfig('meta.zcml', zope.security)()

    @_skip_wo_zope_configuration
    def testFactory(self):
        from zope.component import createObject
        from zope.configuration.xmlconfig import xmlconfig
        from zope.security import proxy
        from zope.security.tests import exampleclass
        self.meta()
        f = configfile('''
<permission id="zope.Foo" title="Zope Foo Permission" />
<class class="zope.security.tests.exampleclass.ExampleClass">
    <factory
      id="test.Example"
      title="Example content"
      description="Example description"
       />
</class>''')
        xmlconfig(f)
        obj = createObject('test.Example')
        self.assertTrue(proxy.isinstance(obj, exampleclass.ExampleClass))



def _pfx(name):
    from zope.security.tests import module
    return module.__name__ + '.' + name

def defineDirectives():
    from zope.security._compat import StringIO
    from zope.configuration.xmlconfig import XMLConfig
    from zope.configuration.xmlconfig import xmlconfig
    import zope.security
    XMLConfig('meta.zcml', zope.security)()
    xmlconfig(StringIO("""<configure
        xmlns='http://namespaces.zope.org/zope'
        i18n_domain='zope'>
       <permission id="zope.Extravagant" title="extravagant" />
       <permission id="zope.Paltry" title="paltry" />
    </configure>"""))

NOTSET = []

P1 = "zope.Extravagant"
P2 = "zope.Paltry"

class TestRequireDirective(unittest.TestCase):

    def setUp(self):
        from zope.interface import implementer
        from zope.security.tests import module
        try:
            from zope.component.testing import setUp
        except ImportError:
            pass
        else:
            setUp()
        defineDirectives()

        class B(object):
            def m1(self):
                return "m1"
            def m2(self):
                return "m2"
        @implementer(module.I)
        class C(B):
            def m3(self):
                return "m3"
            def m4(self):
                return "m4"
        module.test_base = B
        module.test_class = C
        module.test_instance = C()
        self.assertState()

    def tearDown(self):
        from zope.security.tests import module
        module.test_class = None
        try:
            from zope.component.testing import tearDown
        except ImportError:
            pass
        else:
            tearDown()

    def assertState(self, m1P=NOTSET, m2P=NOTSET, m3P=NOTSET):
        #Verify that class, instance, and methods have expected permissions
        from zope.security.checker import selectChecker
        from zope.security.tests import module
        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.permission_id('m1'), (m1P or None))
        self.assertEqual(checker.permission_id('m2'), (m2P or None))
        self.assertEqual(checker.permission_id('m3'), (m3P or None))

    def assertDeclaration(self, declaration, **state):
        from zope.security.tests import module
        apply_declaration(module.template_bracket % declaration)
        self.assertState(**state)

    # "testSimple*" exercises tags that do NOT have children.  This mode
    # inherently sets the instances as well as the class attributes.

    @_skip_wo_zope_configuration
    def test_wo_any_attributes(self):
        from zope.configuration.exceptions import ConfigurationError
        from zope.security.tests import module
        declaration = ('''<class class="%s">
                            <require
                                permission="%s" />
                          </class>'''
                       % (_pfx("test_class"), P1))
        self.assertRaises(ConfigurationError,
                          apply_declaration,
                          module.template_bracket % declaration)

    # "testSimple*" exercises tags that do NOT have children.  This mode
    # inherently sets the instances as well as the class attributes.

    @_skip_wo_zope_configuration
    def testSimpleMethodsPlural(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                attributes="m1 m3"/>
                          </class>'''
                       % (_pfx("test_class"), P1))
        self.assertDeclaration(declaration, m1P=P1, m3P=P1)

    def assertSetattrState(self, m1P=NOTSET, m2P=NOTSET, m3P=NOTSET):
        # Verify that class, instance, and methods have expected permissions
        from zope.security.checker import selectChecker
        from zope.security.tests import module
        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), (m1P or None))
        self.assertEqual(checker.setattr_permission_id('m2'), (m2P or None))
        self.assertEqual(checker.setattr_permission_id('m3'), (m3P or None))

    def assertSetattrDeclaration(self, declaration, **state):
        self.assertSetattrState(**state)

    @_skip_wo_zope_configuration
    def test_set_attributes(self):
        from zope.security.checker import selectChecker
        from zope.security.tests import module
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                set_attributes="m1 m3"/>
                          </class>'''
                       % (_pfx("test_class"), P1))
        apply_declaration(module.template_bracket % declaration)
        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), P1)
        self.assertEqual(checker.setattr_permission_id('m2'), None)
        self.assertEqual(checker.setattr_permission_id('m3'), P1)

    @_skip_wo_zope_configuration
    def test_set_schema(self):
        from zope.component.interface import queryInterface
        from zope.security.checker import selectChecker
        from zope.security.tests import module
        self.assertEqual(queryInterface(_pfx("S")), None)

        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                set_schema="%s"/>
                          </class>'''
                       % (_pfx("test_class"), P1, _pfx("S")))
        apply_declaration(module.template_bracket % declaration)

        self.assertEqual(queryInterface(_pfx("S")), module.S)


        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), None)
        self.assertEqual(checker.setattr_permission_id('m2'), None)
        self.assertEqual(checker.setattr_permission_id('m3'), None)
        self.assertEqual(checker.setattr_permission_id('foo'), P1)
        self.assertEqual(checker.setattr_permission_id('bar'), P1)
        self.assertEqual(checker.setattr_permission_id('baro'), None)

    @_skip_wo_zope_configuration
    def test_multiple_set_schema(self):
        from zope.component.interface import queryInterface
        from zope.security.checker import selectChecker
        from zope.security.tests import module
        self.assertEqual(queryInterface(_pfx("S")), None)
        self.assertEqual(queryInterface(_pfx("S2")), None)

        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                set_schema="%s %s"/>
                          </class>'''
                       % (_pfx("test_class"), P1, _pfx("S"), _pfx("S2")))
        apply_declaration(module.template_bracket % declaration)

        self.assertEqual(queryInterface(_pfx("S")), module.S)
        self.assertEqual(queryInterface(_pfx("S2")), module.S2)


        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), None)
        self.assertEqual(checker.setattr_permission_id('m2'), None)
        self.assertEqual(checker.setattr_permission_id('m3'), None)
        self.assertEqual(checker.setattr_permission_id('foo'), P1)
        self.assertEqual(checker.setattr_permission_id('bar'), P1)
        self.assertEqual(checker.setattr_permission_id('foo2'), P1)
        self.assertEqual(checker.setattr_permission_id('bar2'), P1)
        self.assertEqual(checker.setattr_permission_id('baro'), None)

    @_skip_wo_zope_configuration
    def testSimpleInterface(self):
        from zope.component.interface import queryInterface
        from zope.security.tests import module
        self.assertEqual(queryInterface(_pfx("I")), None)

        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                interface="%s"/>
                          </class>'''
                       % (_pfx("test_class"), P1, _pfx("I")))
        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertDeclaration(declaration, m1P=P1, m2P=P1)

        # Make sure we know about the interfaces
        self.assertEqual(queryInterface(_pfx("I")), module.I)


    @_skip_wo_zope_configuration
    def testMultipleInterface(self):
        from zope.component.interface import queryInterface
        from zope.security.tests import module
        self.assertEqual(queryInterface(_pfx("I3")), None)
        self.assertEqual(queryInterface(_pfx("I4")), None)

        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                interface="  %s
                                             %s  "/>
                          </class>'''
                       % (_pfx("test_class"), P1, _pfx("I3"), _pfx("I4")))
        self.assertDeclaration(declaration, m3P=P1, m2P=P1)

        # Make sure we know about the interfaces
        self.assertEqual(queryInterface(_pfx("I3")), module.I3)
        self.assertEqual(queryInterface(_pfx("I4")), module.I4)

    # "testComposite*" exercises tags that DO have children.
    # "testComposite*TopPerm" exercises tags with permission in containing tag.
    # "testComposite*ElementPerm" exercises tags w/permission in children.

    @_skip_wo_zope_configuration
    def testCompositeNoPerm(self):
        # Establish rejection of declarations lacking a permission spec.
        from zope.configuration.xmlconfig import ZopeXMLConfigurationError
        declaration = ('''<class class="%s">
                            <require
                                attributes="m1"/>
                          </class>'''
                       % (_pfx("test_class")))
        self.assertRaises(ZopeXMLConfigurationError,
                          self.assertDeclaration,
                          declaration)



    @_skip_wo_zope_configuration
    def testCompositeMethodsPluralElementPerm(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                attributes="m1 m3"/>
                          </class>'''
                       % (_pfx("test_class"), P1))
        self.assertDeclaration(declaration,
                               m1P=P1, m3P=P1)

    @_skip_wo_zope_configuration
    def testCompositeInterfaceTopPerm(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                interface="%s"/>
                          </class>'''
                       % (_pfx("test_class"), P1, _pfx("I")))
        self.assertDeclaration(declaration,
                               m1P=P1, m2P=P1)


    @_skip_wo_zope_configuration
    def testSubInterfaces(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                interface="%s"/>
                          </class>'''
                       % (_pfx("test_class"), P1, _pfx("I2")))
        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertDeclaration(declaration, m1P=P1, m2P=P1)


    @_skip_wo_zope_configuration
    def testMimicOnly(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                attributes="m1 m2"/>
                          </class>
                          <class class="%s">
                            <require like_class="%s" />
                          </class>
                          ''' % (_pfx("test_base"), P1,
                _pfx("test_class"), _pfx("test_base")))
        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertDeclaration(declaration,
                               m1P=P1, m2P=P1)


    @_skip_wo_zope_configuration
    def testMimicAsDefault(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                attributes="m1 m2"/>
                          </class>
                          <class class="%s">
                            <require like_class="%s" />
                            <require
                                permission="%s"
                                attributes="m2 m3"/>
                          </class>
                          ''' % (_pfx("test_base"), P1,
                _pfx("test_class"), _pfx("test_base"), P2))

        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertDeclaration(declaration,
                               m1P=P1, m2P=P2, m3P=P2)


def apply_declaration(declaration):
    '''Apply the xmlconfig machinery.'''
    from zope.security._compat import StringIO
    from zope.configuration.xmlconfig import xmlconfig
    return xmlconfig(StringIO(declaration))


@_skip_wo_zope_configuration
def make_dummy():
    from zope.interface import Interface
    import zope.security.zcml
    from zope.security._compat import _u
    global IDummy
    class IDummy(Interface):
        perm = zope.security.zcml.Permission(title=_u(''))


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

    return unittest.TestSuite((
        unittest.makeSuite(TestClassDirective),
        unittest.makeSuite(TestFactorySubdirective),
        unittest.makeSuite(TestFactoryDirective),
        unittest.makeSuite(TestRequireDirective),
        unittest.makeSuite(DirectivesTest),
    ))
