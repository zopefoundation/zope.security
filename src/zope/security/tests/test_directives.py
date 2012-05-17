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
"""Component Directives Tests
"""
import re
import unittest
import pprint
from cStringIO import StringIO
from doctest import DocTestSuite

import zope.component
from zope.interface import implementer
from zope.component.interface import queryInterface

try:
    from zope.configuration.xmlconfig import xmlconfig, XMLConfig
    from zope.configuration.xmlconfig import ZopeXMLConfigurationError
except ImportError:
    HAVE_ZCML = False
else:
    HAVE_ZCML = True

from zope.security.checker import selectChecker
from zope.security import proxy

import zope.security
from zope.component.testing import PlacelessSetup

from zope.security.tests import module, exampleclass

# TODO: tests for other directives needed

atre = re.compile(' at [0-9a-fA-Fx]+')

class Context(object):
    actions = ()

    def action(self, discriminator, callable, args):
        self.actions += ((discriminator, callable, args), )

    def __repr__(self):
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

def definePermissions():
    XMLConfig('meta.zcml', zope.security)()


class ParticipationStub(object):

    def __init__(self, principal):
        self.principal = principal
        self.interaction = None


def configfile(s):
    return StringIO("""<configure
      xmlns='http://namespaces.zope.org/zope'
      i18n_domain='zope'>
      %s
      </configure>
      """ % s)

class TestFactoryDirective(PlacelessSetup, unittest.TestCase):
    def setUp(self):
        super(TestFactoryDirective, self).setUp()
        XMLConfig('meta.zcml', zope.security)()

    def testFactory(self):
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
        obj = zope.component.createObject('test.Example')
        self.failUnless(proxy.isinstance(obj, exampleclass.ExampleClass))



PREFIX = module.__name__ + '.'

def defineDirectives():
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

class TestRequireDirective(PlacelessSetup, unittest.TestCase):

    def setUp(self):
        super(TestRequireDirective, self).setUp()
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
        PlacelessSetup.tearDown(self)
        module.test_class = None

    def assertState(self, m1P=NOTSET, m2P=NOTSET, m3P=NOTSET):
        "Verify that class, instance, and methods have expected permissions."

        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.permission_id('m1'), (m1P or None))
        self.assertEqual(checker.permission_id('m2'), (m2P or None))
        self.assertEqual(checker.permission_id('m3'), (m3P or None))

    def assertDeclaration(self, declaration, **state):
        apply_declaration(module.template_bracket % declaration)
        self.assertState(**state)

    # "testSimple*" exercises tags that do NOT have children.  This mode
    # inherently sets the instances as well as the class attributes.

    def testSimpleMethodsPlural(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                attributes="m1 m3"/>
                          </class>'''
                       % (PREFIX+"test_class", P1))
        self.assertDeclaration(declaration, m1P=P1, m3P=P1)

    def assertSetattrState(self, m1P=NOTSET, m2P=NOTSET, m3P=NOTSET):
        "Verify that class, instance, and methods have expected permissions."

        from zope.security.checker import selectChecker

        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), (m1P or None))
        self.assertEqual(checker.setattr_permission_id('m2'), (m2P or None))
        self.assertEqual(checker.setattr_permission_id('m3'), (m3P or None))

    def assertSetattrDeclaration(self, declaration, **state):
        self.assertSetattrState(**state)

    def test_set_attributes(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                set_attributes="m1 m3"/>
                          </class>'''
                       % (PREFIX+"test_class", P1))
        apply_declaration(module.template_bracket % declaration)
        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), P1)
        self.assertEqual(checker.setattr_permission_id('m2'), None)
        self.assertEqual(checker.setattr_permission_id('m3'), P1)

    def test_set_schema(self):

        self.assertEqual(queryInterface(PREFIX+"S"), None)

        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                set_schema="%s"/>
                          </class>'''
                       % (PREFIX+"test_class", P1, PREFIX+"S"))
        apply_declaration(module.template_bracket % declaration)

        self.assertEqual(queryInterface(PREFIX+"S"), module.S)


        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), None)
        self.assertEqual(checker.setattr_permission_id('m2'), None)
        self.assertEqual(checker.setattr_permission_id('m3'), None)
        self.assertEqual(checker.setattr_permission_id('foo'), P1)
        self.assertEqual(checker.setattr_permission_id('bar'), P1)
        self.assertEqual(checker.setattr_permission_id('baro'), None)

    def test_multiple_set_schema(self):

        self.assertEqual(queryInterface(PREFIX+"S"), None)
        self.assertEqual(queryInterface(PREFIX+"S2"), None)

        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                set_schema="%s %s"/>
                          </class>'''
                       % (PREFIX+"test_class", P1, PREFIX+"S", PREFIX+"S2"))
        apply_declaration(module.template_bracket % declaration)

        self.assertEqual(queryInterface(PREFIX+"S"), module.S)
        self.assertEqual(queryInterface(PREFIX+"S2"), module.S2)


        checker = selectChecker(module.test_instance)
        self.assertEqual(checker.setattr_permission_id('m1'), None)
        self.assertEqual(checker.setattr_permission_id('m2'), None)
        self.assertEqual(checker.setattr_permission_id('m3'), None)
        self.assertEqual(checker.setattr_permission_id('foo'), P1)
        self.assertEqual(checker.setattr_permission_id('bar'), P1)
        self.assertEqual(checker.setattr_permission_id('foo2'), P1)
        self.assertEqual(checker.setattr_permission_id('bar2'), P1)
        self.assertEqual(checker.setattr_permission_id('baro'), None)

    def testSimpleInterface(self):

        self.assertEqual(queryInterface(PREFIX+"I"), None)

        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                interface="%s"/>
                          </class>'''
                       % (PREFIX+"test_class", P1, PREFIX+"I"))
        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertDeclaration(declaration, m1P=P1, m2P=P1)

        # Make sure we know about the interfaces
        self.assertEqual(queryInterface(PREFIX+"I"), module.I)


    def testMultipleInterface(self):

        self.assertEqual(queryInterface(PREFIX+"I3"), None)
        self.assertEqual(queryInterface(PREFIX+"I4"), None)

        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                interface="  %s
                                             %s  "/>
                          </class>'''
                       % (PREFIX+"test_class", P1, PREFIX+"I3", PREFIX+"I4"))
        self.assertDeclaration(declaration, m3P=P1, m2P=P1)

        # Make sure we know about the interfaces
        self.assertEqual(queryInterface(PREFIX+"I3"), module.I3)
        self.assertEqual(queryInterface(PREFIX+"I4"), module.I4)

    # "testComposite*" exercises tags that DO have children.
    # "testComposite*TopPerm" exercises tags with permission in containing tag.
    # "testComposite*ElementPerm" exercises tags w/permission in children.

    def testCompositeNoPerm(self):
        # Establish rejection of declarations lacking a permission spec.
        declaration = ('''<class class="%s">
                            <require
                                attributes="m1"/>
                          </class>'''
                       % (PREFIX+"test_class"))
        self.assertRaises(ZopeXMLConfigurationError,
                          self.assertDeclaration,
                          declaration)



    def testCompositeMethodsPluralElementPerm(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                attributes="m1 m3"/>
                          </class>'''
                       % (PREFIX+"test_class", P1))
        self.assertDeclaration(declaration,
                               m1P=P1, m3P=P1)

    def testCompositeInterfaceTopPerm(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                interface="%s"/>
                          </class>'''
                       % (PREFIX+"test_class", P1, PREFIX+"I"))
        self.assertDeclaration(declaration,
                               m1P=P1, m2P=P1)


    def testSubInterfaces(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                interface="%s"/>
                          </class>'''
                       % (PREFIX+"test_class", P1, PREFIX+"I2"))
        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertDeclaration(declaration, m1P=P1, m2P=P1)


    def testMimicOnly(self):
        declaration = ('''<class class="%s">
                            <require
                                permission="%s"
                                attributes="m1 m2"/>
                          </class>
                          <class class="%s">
                            <require like_class="%s" />
                          </class>
                          ''' % (PREFIX+"test_base", P1,
                PREFIX+"test_class", PREFIX+"test_base"))
        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertDeclaration(declaration,
                               m1P=P1, m2P=P1)


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
                          ''' % (PREFIX+"test_base", P1,
                PREFIX+"test_class", PREFIX+"test_base", P2))

        # m1 and m2 are in the interface, so should be set, and m3 should not:
        self.assertDeclaration(declaration,
                               m1P=P1, m2P=P2, m3P=P2)


def apply_declaration(declaration):
    '''Apply the xmlconfig machinery.'''
    return xmlconfig(StringIO(declaration))


def test_suite():
    if not HAVE_ZCML:
        return unittest.TestSuite()

    return unittest.TestSuite((
        unittest.makeSuite(TestFactoryDirective),
        unittest.makeSuite(TestRequireDirective),
        DocTestSuite(),
        ))
