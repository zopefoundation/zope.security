=================================
 Hacking on :mod:`zope.security`
=================================


Getting the Code
================

The main repository for :mod:`zope.security` is in the Zope Foundation
Github repository:

  https://github.com/zopefoundation/zope.security

You can get a read-only checkout from there:

.. code-block:: sh

   $ git clone https://github.com/zopefoundation/zope.security.git

or fork it and get a writeable checkout of your fork:

.. code-block:: sh

   $ git clone git@github.com/jrandom/zope.security.git

The project also mirrors the trunk from the Github repository as a
Bazaar branch on Launchpad:

https://code.launchpad.net/zope.security

You can branch the trunk from there using Bazaar:

.. code-block:: sh

   $ bzr branch lp:zope.security


Working in a ``virtualenv``
===========================

Installing
----------

If you use the ``virtualenv`` package to create lightweight Python
development environments, you can run the tests using nothing more
than the ``python`` binary in a virtualenv.  First, create a scratch
environment:

.. code-block:: sh

   $ /path/to/virtualenv --no-site-packages /tmp/hack-zope.security

Next, get this package registered as a "development egg" in the
environment:

.. code-block:: sh

   $ /tmp/hack-zope.security/bin/pip install -e .[test]

Running the tests
-----------------

Then, you can run the tests using the zope.testrunner (or a test
runner of your choice):

.. code-block:: sh

   $ /tmp/hack-zope.security/bin/zope-testrunner --test-path=src
   Running zope.testrunner.layer.UnitTests tests:
     Set up zope.testrunner.layer.UnitTests in 0.000 seconds.
     Running:

     Ran 742 tests with 0 failures, 0 errors, 36 skipped in 0.253 seconds.
   Tearing down left over layers:
     Tear down zope.testrunner.layer.UnitTests in 0.000 seconds.

If you have the :mod:`coverage` package installed in the virtualenv,
you can see how well the tests cover the code:

.. code-block:: sh

   $ /tmp/hack-zope.security/bin/pip install coverage
   ...
   $ coverage run -m zope.testrunner --test-path=src
   ...
   $ coverage report
   Name                              Stmts   Miss  Cover   Missing
   ---------------------------------------------------------------
   zope/security.py                      4      0   100%
   zope/security/_compat.py              9      0   100%
   zope/security/_definitions.py        11      0   100%
   zope/security/adapter.py             45      0   100%
   zope/security/checker.py            333      0   100%
   zope/security/decorator.py           33      0   100%
   zope/security/i18n.py                 4      0   100%
   zope/security/interfaces.py          65      0   100%
   zope/security/management.py          62      0   100%
   zope/security/metaconfigure.py      108      0   100%
   zope/security/metadirectives.py      38      0   100%
   zope/security/permission.py          46      0   100%
   zope/security/protectclass.py        39      0   100%
   zope/security/proxy.py              164     19    88%   55, 86, 97, 119-121, 127-129, 143-144, 153-154, 158-159, 163-164, 298, 330
   zope/security/simplepolicies.py      32      0   100%
   zope/security/zcml.py                43      0   100%
   ---------------------------------------------------------------
   TOTAL                              1036     19    98%
   ----------------------------------------------------------------------
   Ran 655 tests in 0.000s

   OK


Building the documentation
--------------------------

:mod:`zope.security` uses the nifty :mod:`Sphinx` documentation system
for building its docs.  Using the same virtualenv you set up to run the
tests, you can build the docs:

.. code-block:: sh

   $ /tmp/hack-zope.security/bin/pip install -e .[docs]
   ...
   $ cd docs
   $ PATH=/tmp/hack-zope.security/bin:$PATH make html
   sphinx-build -b html -d _build/doctrees   . _build/html
   ...
   build succeeded.

   Build finished. The HTML pages are in _build/html.

You can also test the code snippets in the documentation:

.. code-block:: sh

   $ PATH=/tmp/hack-zope.security/bin:$PATH make doctest
   sphinx-build -b doctest -d _build/doctrees   . _build/doctest
   ...
   running tests...

   Document: api/zcml
   ------------------
   1 items passed all tests:
     23 tests in default
   23 tests in 1 items.
   23 passed and 0 failed.
   Test passed.

   Document: api/proxy
   -------------------
   1 items passed all tests:
     11 tests in default
   11 tests in 1 items.
   11 passed and 0 failed.
   Test passed.
   1 items passed all tests:
      1 tests in default (cleanup code)
   1 tests in 1 items.
   1 passed and 0 failed.
   Test passed.

   Document: api/permission
   ------------------------
   1 items passed all tests:
     35 tests in default
   35 tests in 1 items.
   35 passed and 0 failed.
   Test passed.
   1 items passed all tests:
      1 tests in default (cleanup code)
   1 tests in 1 items.
   1 passed and 0 failed.
   Test passed.

   Document: api/checker
   ---------------------
   1 items passed all tests:
    356 tests in default
   356 tests in 1 items.
   356 passed and 0 failed.
   Test passed.

   Document: api/decorator
   -----------------------
   1 items passed all tests:
     53 tests in default
   53 tests in 1 items.
   53 passed and 0 failed.
   Test passed.
   1 items passed all tests:
      1 tests in default (cleanup code)
   1 tests in 1 items.
   1 passed and 0 failed.
   Test passed.

   Doctest summary
   ===============
     478 tests
       0 failures in tests
       0 failures in setup code
       0 failures in cleanup code


Using :mod:`zc.buildout`
========================

Setting up the buildout
-----------------------

:mod:`zope.security` ships with its own :file:`buildout.cfg` file and
:file:`bootstrap.py` for setting up a development buildout:

.. code-block:: sh

   $ /path/to/python2.6 bootstrap.py
   ...
   Generated script '.../bin/buildout'
   $ bin/buildout
   Develop: '/home/jrandom/projects/Zope/BTK/security/.'
   ...

Running the tests
-----------------

You can now run the tests:

.. code-block:: sh

   $ bin/test --all
   Running zope.testing.testrunner.layer.UnitTests tests:
     Set up zope.testing.testrunner.layer.UnitTests in 0.000 seconds.
     Ran 643 tests with 0 failures and 0 errors in 0.000 seconds.
   Tearing down left over layers:
     Tear down zope.testing.testrunner.layer.UnitTests in 0.000 seconds.



Using :mod:`tox`
================

Running Tests on Multiple Python Versions
-----------------------------------------

`tox <http://tox.testrun.org/latest/>`_ is a Python-based test automation
tool designed to run tests against multiple Python versions.  It creates
a ``virtualenv`` for each configured version, installs the current package
and configured dependencies into each ``virtualenv``, and then runs the
configured commands.

:mod:`zope.security` configures the following :mod:`tox` environments via
its ``tox.ini`` file:

- The ``py27``, ``py34``, ``py35``, ``pypy``, etc, environments
  builds a ``virtualenv`` with the appropriate interpreter,
  installs :mod:`zope.security` and dependencies, and runs the tests.

- The ``py27-pure`` and ``py33-pure`` environments build a ``virtualenv``
  with the appropriate interpreter, installs :mod:`zope.security` and
  dependencies **without compiling C extensions**, and runs the tests
  via ``python setup.py test -q``.

- The ``coverage`` environment builds a ``virtualenv``, runs all the
  tests under :mod:`coverage`, and prints a report to stdout.

- The ``docs`` environment builds a virtualenv and then builds the
  docs and exercises the doctest snippets.

This example requires that you have a working ``python2.7`` on your path,
as well as installing ``tox``:

.. code-block:: sh

   $ tox -e py27
   GLOB sdist-make: .../zope.security/setup.py
   py27 sdist-reinst: .../zope.security/.tox/dist/zope.security-4.0.2dev.zip
   py27 runtests: commands[0]
   ...................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................
   ----------------------------------------------------------------------
   Ran 643 tests in 0.000s

   OK
   ___________________________________ summary ____________________________________
   py26: commands succeeded
   congratulations :)

Running ``tox`` with no arguments runs all the configured environments,
including building the docs and testing their snippets:

.. code-block:: sh

   $ tox
   GLOB sdist-make: .../zope.security/setup.py
   py26 sdist-reinst: .../zope.security/.tox/dist/zope.security-4.0.2dev.zip
   py26 runtests: commands[0]
   ...
   Doctest summary
   ===============
    478 tests
      0 failures in tests
      0 failures in setup code
      0 failures in cleanup code
   build succeeded.
   ___________________________________ summary ____________________________________
   py26: commands succeeded
   py27: commands succeeded
   py27-pure: commands succeeded
   pypy: commands succeeded
   py32: commands succeeded
   py33: commands succeeded
   py33-pure: commands succeeded
   py34: commands succeeded
   coverage: commands succeeded
   docs: commands succeeded
   congratulations :)


Contributing to :mod:`zope.security`
====================================

Submitting a Bug Report
-----------------------

:mod:`zope.security` tracks its bugs on Github:

  https://github.com/zopefoundation/zope.security/issues

Please submit bug reports and feature requests there.


Sharing Your Changes
--------------------

.. note::

   Please ensure that all tests are passing before you submit your code.
   If possible, your submission should include new tests for new features
   or bug fixes, although it is possible that you may have tested your
   new code by updating existing tests.

If have made a change you would like to share, the best route is to fork
the Githb repository, check out your fork, make your changes on a branch
in your fork, and push it.  You can then submit a pull request from your
branch:

  https://github.com/zopefoundation/zope.security/pulls
