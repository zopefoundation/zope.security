=============================================
 Untrusted Interpreters and Security Proxies
=============================================

Untrusted programs are executed by untrusted interpreters.  Untrusted
interpreters make use of security proxies to prevent un-mediated
access to assets.  An untrusted interpreter defines an environment for
running untrusted programs. All objects within the environment are
either:

- "safe" objects created internally by the environment or created in
  the course of executing the untrusted program, or

- "basic" objects

- security-proxied non-basic objects

The environment includes proxied functions for accessing objects
outside of the environment.  These proxied functions provide the only
way to access information outside the environment.  Because these
functions are proxied, as described below, any access to objects
outside the environment is mediated by the target security functions.

Safe objects are objects whose operations, except for attribute
retrieval, and methods access only information stored within the
objects or passed as arguments.  Safe objects contained within the
interpreter environment can contain only information that is already
in the environment or computed directly from information that is
included in the environment. For this reason, safe objects created
within the environment cannot be used to directly access information
outside the environment.

Safe objects have some attributes that could (very) indirectly be used
to access assets. For this reason, an untrusted interpreter always
proxies the results of attribute accesses on a safe objects.

Basic objects are safe objects that are used to represent elemental
data values such as strings and numbers.  Basic objects require a
lower level of protection than non-basic objects, as will be described
detail in a later section.

Security proxies mediate all object operations.  Any operation
access is checked to see whether a subject is authorized to perform
the operation.  All operation results other than basic objects are, in
turn, security proxied.  Security proxies will be described in greater
detail in a later section.  Any operation on a security proxy that
results in a non-basic object is also security proxied.

All external resources needed to perform an operation are security
proxied.

Let's consider the trusted interpreter for evaluating URLs.  In
operation 1 of the example, the interpreter uses a proxied method for
getting the system root object.  Because the method is proxied, the
result of calling the method and the operation is also proxied.

The interpreter has a function for traversing objects.  This function
is proxied.  When traversing an object, the function is passed an
object and a name.  In operation 2, the function is passed the result
of operation 1, which is the proxied root object and the name 'A'.  We
may traverse an object by invoking an operation on it.  For example,
we may use an operation to get a sub-object. Because any operation on a
proxied object returns a proxied object or a basic object, the result
is either a proxied object or a basic object.  Traversal may also look
up a component.  For example, in operation 1, we might look up a
presentation component named "A" for the root object.  In this case,
the external object is not proxied, but, when it is returned from the
traversal function, it is proxied (unless it is a a basic object)
because the traversal function is proxied, and the result of calling a
proxied function is proxied (unless the result is a basic object).
Operation 3 proceeds in the same way.

When we get to operation 4, we use a function for computing the
default presentation of the result of operation 3. As with traversal,
the result of getting the default presentation is either a proxied
object or a basic object because the function for getting the default
presentation is proxied.

When we get to the last operation, we have either a proxied object or a
basic object.  If the result of operation 4 is a basic object, we
simply convert it to a string and return it as the result page.  If
the result of operation 4 is a non-basic object, we invoke a render
operation on it and return the result as a string.

Note that an untrusted interpreter may or may not provide protection
against excessive resource usage.  Different interpreters will provide
different levels of service with respect to limitations on resource
usage.

If an untrusted interpreter performs an attribute access, the trusted
interpreter must proxy the result unless the result is a basic object.

In summary, an untrusted interpreter assures that any access to assets
is mediated through security proxies by creating an environment to run
untrusted code and making sure that:

- The only way to access anything from outside of the environment is
  to call functions that are proxied in the environment.

- Results of any attribute access in the environment are proxied
  unless the results are basic objects.

Security proxies
================

Security proxies are objects that wrap and mediate access to objects.

The Python programming language used by Zope defines a set of specific
named low-level operations.  In addition to operations, Python objects
can have attributes, used to represent data and methods.  Attributes
are accessed using a dot notation. Applications can, and usually do,
define methods to provide extended object behaviors.  Methods are
accessed as attributes through the low-level operation named
"__getattribute__".  The Python code::

   a.b()

invokes 2 operations:

  1. Use the low-level ``__getattribute__`` operation with the name "b".

  2. Use the low-level ``__call__`` operation on the result of the first
     operation.

For all operations except the ``__getattribute__`` and
``__setattribute__`` operations, security proxies have a permission
value defined by the permission-declaration subsystem.  Two special
permission values indicate that access is either forbidden (never
allowed) or public (always allowed).  For all other permission values,
the authorization subsystem is used to decide whether the subject has
the permission for the proxied object.  If the subject has the
permission, then access to the operation is allowed. Otherwise, access
is denied.

For getting or setting attributes, a proxy has permissions for getting
and a permission for setting attribute values for a given attribute
name.  As described above, these permissions may be one of the two
special permission values indicating forbidden or public access, or
another permission value that must be checked with the authorization
system.

For all objects, Zope defines the following operations to be always public:

  comparison
     "__lt__", "__le__", "__eq__", "__gt__", "__ge__", "__ne__"

  hash
     "__hash__"

  boolean value
     "__nonzero__"

  class introspection
     "__class__"

  interface introspection
    "__providedBy__", "__implements__"

  adaptation
    "__conform__"

  low-level string representation
    "__repr__"

The result of an operation on a proxied object is a security proxy
unless the result is a basic value.

Basic objects
=============

Basic objects are safe immutable objects that contain only immutable
subobjects. Examples of basic objects include:

- Strings,

- Integers (long and normal),

- Floating-point objects,

- Date-time objects,

- Boolean objects (True and False), and

- The special (nil) object, None.

Basic objects are safe, so, as described earlier, operations on basic
objects, other than attribute access, use only information contained
within the objects or information passed to them.  For this reason,
basic objects cannot be used to access information outside of the
untrusted interpreter environment.

The decision not to proxy basic objects is largely an optimization.
It allows low-level safe computation to be performed without
unnecessary overhead,

Note that a basic object could contain sensitive information, but such
a basic object would need to be obtained by making a call on a proxied
object.  Therefore, the access to the basic object in the first place
is mediated by the security functions.

Rationale for mutable safe objects
==================================

Some safe objects are not basic. For these objects, we proxy the
objects if they originate from outside of the environment.  We do this
for two reasons:

1. Non-basic objects from outside the environment need to be proxied
   to prevent unauthorized access to information.

2. We need to prevent un-mediated change of information from outside of
   the environment.

We don't proxy safe objects created within the environment.  This is
safe to do because such safe objects can contain and provide access to
information already in the environment.  Sometimes the interpreter or
the interpreted program needs to be able to create simple data
containers to hold information computed in the course of the program
execution.  Several safe container types are provided for this
purpose.

.. _proxy-known-issues:

Known Issues With Proxies
=========================

Security proxies (proxies in general) are not perfect in Python. There
are some things that they cannot transparently proxy.

.. _isinstance-and-proxies:

isinstance and proxies
----------------------

A proxied object cannot proxy its type (although it does proxy its ``__class__``):

.. doctest::

    >>> from zope.security.proxy import ProxyFactory
    >>> class Object(object):
    ...     pass
    >>> target = Object()
    >>> target.__class__
    <class 'Object'>
    >>> type(target)
    <class 'Object'>
    >>> proxy = ProxyFactory(target, None)
    >>> proxy.__class__
    <class 'Object'>
    >>> type(proxy)
    <... 'zope.security...Proxy...'>

This means that the builtin :func:`isinstance` may return unexpected
results:

.. doctest::

    >>> isinstance(target, Object)
    True
    >>> isinstance(proxy, Object)
    False

There are two workarounds. The safest is to use
:func:`zope.security.proxy.isinstance`, which takes specifically this
into account (in modules that will be dealing with a number of
proxies, it is common to simply place ``from zope.security.proxy
import isinstance`` at the top of the file to override the builtin
:func:`isinstance`; we won't show that here for clarity):

.. doctest::

    >>> import zope.security.proxy
    >>> zope.security.proxy.isinstance(target, Object)
    True
    >>> zope.security.proxy.isinstance(proxy, Object)
    True

Alternatively, you can manually remove the security proxy (or indeed,
all proxies) with :func:`zope.security.proxy.removeSecurityProxy` or
:func:`zope.proxy.removeAllProxies`, respectively, before calling
:func:`isinstance`:

.. doctest::

    >>> from zope.security.proxy import removeSecurityProxy
    >>> isinstance(removeSecurityProxy(target), Object)
    True
    >>> isinstance(removeSecurityProxy(proxy), Object)
    True


issubclass and proxies
----------------------

Security proxies will proxy the return value of ``__class__``: it will
be a proxy around the real class of the proxied value. This causes
failures with ``issubclass``:

.. doctest::

    >>> from zope.security.proxy import ProxyFactory
    >>> class Object(object):
    ...     pass
    >>> target = Object()
    >>> target.__class__ is Object
    True
    >>> proxy = ProxyFactory(target, None)
    >>> proxy.__class__
    <class 'Object'>
    >>> proxy.__class__ is Object
    False
    >>> issubclass(proxy.__class__, Object)
    Traceback (most recent call last):
    ...
    TypeError: issubclass() arg 1 must be a class

Although the above is a contrived example, using :class:`abstract base
classes <abc.ABCMeta>` can cause it to arise quite
unexpectedly:

.. doctest::

    >>> from collections import Mapping
    >>> from abc import ABCMeta
    >>> isinstance(Mapping, ABCMeta)
    True
    >>> isinstance(proxy, Mapping)
    Traceback (most recent call last):
    ...
    TypeError: issubclass() arg 1 must be a class


In this case, the workarounds described :ref:`above <isinstance-and-proxies>` also work:

.. doctest::

    >>> zope.security.proxy.isinstance(proxy, Mapping)
    False
    >>> isinstance(removeSecurityProxy(proxy), Mapping)
    False

.. We need to clean up the caching that ABC does on
.. pure-python platforms to make sure that we get where
.. we expect to be when we construct LogRecord; otherwise
.. the ProxyMetaclass may be in the negative cache, bypassing
.. the issubclass() calls we expect.

.. doctest::
    :hide:

    >>> if hasattr(ABCMeta, '_abc_invalidation_counter'):
    ...     ABCMeta._abc_invalidation_counter += 1

logging
~~~~~~~

Starting with `Python 2.7.7 <https://bugs.python.org/issue21172>`_,
the :class:`logging.LogRecord`  makes exactly the above ``isinstance``
call:

.. doctest::

    >>> from logging import LogRecord
    >>> LogRecord("name", 1, "/path/to/file", 1,
    ...     "The message %s", (proxy,), None)
    Traceback (most recent call last):
    ...
    TypeError: issubclass() arg 1 must be a class

`Possible workarounds include <https://github.com/zopefoundation/zope.security/issues/26>`_:

- Carefully removing security proxies of objects before passing them
  to the logging system.
- Monkey-patching the logging system to use
  :func:`zope.security.proxy.isinstance` which does this
  automatically::

      import zope.security.proxy
      import logging
      logging.isinstance = zope.security.proxy.isinstance
- Using :func:`logging.setLogRecordfactory` to set a custom
  ``LogRecord`` subclass that unwraps any security proxies before they
  are given to the super class. Note that this is only available on
  Python 3. On Python 2, it might be possible to achieve a similar
  result with a custom :func:`logger class <logging.setLoggerClass>`:

.. doctest::

    >>> from zope.security.proxy import removeSecurityProxy
    >>> class UnwrappingLogRecord(LogRecord):
    ...     def __init__(self, name, level, pathname, lineno,
    ...                  msg, args, exc_info, *largs, **kwargs):
    ...         args = [removeSecurityProxy(x) for x in args]
    ...         LogRecord.__init__(self, name, level, pathname,
    ...                            lineno, msg, args, exc_info, *largs, **kwargs)
    ...     def __repr__(self):
    ...         return '<UnwrappingLogRecord>'
    >>> UnwrappingLogRecord("name", 1, "/path/to/file", 1,
    ...                     "The message %s", (proxy,), None)
    <UnwrappingLogRecord>


Each specific application will have to determine what solution is
correct for its security model.
