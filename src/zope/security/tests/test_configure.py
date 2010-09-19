import doctest
import unittest


def test_suite():
    suite = unittest.TestSuite()

    try:
        import zope.configuration
    except ImportError:
        pass
    else:
        from zope.component.testing import setUp, tearDown
        suite.addTest(doctest.DocFileSuite('configure.txt',
                      setUp=setUp, tearDown=tearDown))

    return suite
