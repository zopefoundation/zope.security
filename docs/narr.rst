Untrusted interpreters
======================

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
----------------

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

  1. Use the low-level `__getattribute__` operation with the name "b".

  2. Use the low-level '__call__' operation on the result of the first
     operation.

For all operations except the `__getattribute__` and
`__setattribute__` operations, security proxies have a permission
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
-------------

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
----------------------------------

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


Safe Builtins
=============

When executing untrusted Python code, we need to make sure that we
only give the code access to safe, basic or proxied objects. This
included the builtin objects provided to Python code through a special
__builtins__ module in globals.  The `builtins` module provides a
suitable module object:

.. doctest::

   >>> from zope.security.untrustedpython.builtins import SafeBuiltins
   >>> d = {'__builtins__': SafeBuiltins}
   >>> exec 'x = str(1)' in d
   >>> d['x']
   '1'

The object is immutable:

.. doctest::

   >>> SafeBuiltins.foo = 1
   Traceback (most recent call last):
   ...
   AttributeError: foo

   >>> del SafeBuiltins['getattr']
   Traceback (most recent call last):
   ...
   TypeError: object does not support item deletion



   Exception raised:
   ...
   TypeError: object does not support item deletion

(Note that you can mutate it through its `__dict__` attribute,
 however, when combined with the untrusted code compiler, getting the
 `__dict__` attribute will return a proxied object that will prevent
 mutation.)

It contains items with keys that are all strings and values that are
either proxied or are basic types:

.. doctest::

   >>> from zope.security.proxy import Proxy
   >>> for key, value in SafeBuiltins.__dict__.items():
   ...     if not isinstance(key, str):
   ...         raise TypeError(key)
   ...     if value is not None and not isinstance(value, (Proxy, int, str)):
   ...         raise TypeError(value, key)

It doesn't contain unsafe items, such as eval, globals, etc:

.. doctest::

   >>> SafeBuiltins.eval
   Traceback (most recent call last):
   ...
   AttributeError: 'ImmutableModule' object has no attribute 'eval'
   >>> SafeBuiltins.globals
   Traceback (most recent call last):
   ...
   AttributeError: 'ImmutableModule' object has no attribute 'globals'

The safe builtins also contains a custom __import__ function.

.. doctest::

   >>> imp = SafeBuiltins.__import__

As with regular import, it only returns the top-level package if no
fromlist is specified:

.. doctest::

   >>> import zope.security
   >>> imp('zope.security') == zope
   True
   >>> imp('zope.security', {}, {}, ['*']) == zope.security
   True

Note that the values returned are proxied:

.. doctest::

   >>> type(imp('zope.security')) is Proxy
   True

This means that, having imported a module, you will only be able to
access attributes for which you are authorized.

Unlike regular __import__, you can only import modules that have been
previously imported.  This is to prevent unauthorized execution of
module-initialization code:

.. doctest::

   >>> security = zope.security
   >>> import sys
   >>> del sys.modules['zope.security']
   >>> imp('zope.security')
   Traceback (most recent call last):
   ...
   ImportError: zope.security

   >>> sys.modules['zope.security'] = security

Package-relative imports are supported (for now):

.. doctest::

   >>> imp('security', {'__name__': 'zope', '__path__': []}) == security
   True
   >>> imp('security', {'__name__': 'zope.foo'}) == zope.security
   True

   >>> imp('security.untrustedpython', {'__name__': 'zope.foo'}) == security
   True
   >>> from zope.security import untrustedpython
   >>> imp('security.untrustedpython', {'__name__': 'zope.foo'}, {}, ['*']
   ...     ) == untrustedpython
   True

Untrusted Python interpreter
============================

The interpreter module provides very basic Python interpreter
support.  It combined untrusted code compilation with safe builtins
and an exec-like API.  The exec_src function can be used to execute
Python source:

.. doctest::

   >>> from zope.security.untrustedpython.interpreter import exec_src
   >>> d = {}
   >>> exec_src("x=1", d)
   >>> d['x']
   1

   >>> exec_src("x=getattr", d)

Note that the safe builtins dictionary is inserted into the
dictionary:

.. doctest::

   >>> from zope.security.untrustedpython.builtins import SafeBuiltins
   >>> d['__builtins__'] == SafeBuiltins
   True

All of the non-basic items in the safe builtins are proxied:

.. doctest::

   >>> exec_src('str=str', d)
   >>> from zope.security.proxy import Proxy
   >>> type(d['str']) is Proxy
   True

Note that, while you can get to the safe `__builtins__`'s dictionary,
you can't use the dictionary to mutate it:

.. doctest::

   >>> from zope.security.interfaces import ForbiddenAttribute

   >>> try: exec_src('__builtins__.__dict__["x"] = 1', d)
   ... except ForbiddenAttribute: print 'Forbidden!'
   Forbidden!

   >>> try: exec_src('del __builtins__.__dict__["str"]', d)
   ... except ForbiddenAttribute: print 'Forbidden!'
   Forbidden!

   >>> try: exec_src('__builtins__.__dict__.update({"x": 1})', d)
   ... except ForbiddenAttribute: print 'Forbidden!'
   Forbidden!

Because the untrusted code compiler is used, you can't use exec,
raise, or try/except statements:

.. doctest::

   >>> exec_src("exec 'x=1'", d)
   Traceback (most recent call last):
   ...
   SyntaxError: Line 1: exec statements are not supported
  
Any attribute-access results will be proxied:

.. doctest::

   >>> exec_src("data = {}\nupdate = data.update\nupdate({'x': 'y'})", d)
   >>> type(d['update']) is Proxy
   True

In this case, we were able to get to and use the update method because
the data dictionary itself was created by the untrusted code and was,
thus, unproxied.

You can compile code yourself and call exec_code instead:

.. doctest::

   >>> from zope.security.untrustedpython.rcompile import compile
   >>> code = compile('x=2', '<mycode>', 'exec')
   >>> d = {}
   >>> from zope.security.untrustedpython.interpreter import exec_code
   >>> exec_code(code, d)
   >>> d['x']
   2

This is useful if you are going to be executing the same expression
many times, as you can avoid the cost of repeated comilation.

Compiled Programs
-----------------

A slightly higher-level interface is provided by compiled programs.
These make it easier to safetly safe the results of compilation:

.. doctest::

   >>> from zope.security.untrustedpython.interpreter import CompiledProgram
   >>> p = CompiledProgram('x=2')
   >>> d = {}
   >>> p.exec_(d)
   >>> d['x']
   2
    
When you execute a compiled program, you can supply an object with a
write method to get print output:

.. doctest::

   >>> p = CompiledProgram('print "Hello world!"')
   >>> import cStringIO
   >>> f = cStringIO.StringIO()
   >>> p.exec_({}, output=f)
   >>> f.getvalue()
   'Hello world!\n'


Compiled Expressions
--------------------

You can also precompile expressions:

.. doctest::

   >>> from zope.security.untrustedpython.interpreter import CompiledExpression
   >>> p = CompiledExpression('x*2')
   >>> p.eval({'x': 2})
   4

Support for Restricted Python Code
==================================

This package provides a way to compile
untrusted Python code so that it can be executed safely.

This form of restricted Python assumes that security proxies will be
used to protect assets.  Given this, the only thing that actually
needs to be done differently by the generated code is to:

- Ensure that all attribute lookups go through a safe version of the getattr()
  function that's been provided in the built-in functions used in the
  execution environment.  

- Prevent exec statements. (Later, we could possibly make exec safe.)

- Print statements always go to an output that is provided as a
  global, rather than having an implicit sys.output.

- Prevent try/except and raise statements. This is mainly because they
  don't work properly in the presense of security proxies.  Try/except
  statements will be made to work in the future.

No other special treatment is needed to support safe expression
evaluation.

The implementation makes use of the `RestrictedPython` package,
originally written for Zope 2.  There is a new AST re-writer in
`zope.security.untrustedpython.rcompile` which performs the
tree-transformation, and a top-level `compile()` function in
`zope.security.untrustedpython.rcompile`; the later is what client
applications are expected to use.

The signature of the `compile()` function is very similar to that of
Python's built-in `compile()` function::

  compile(source, filename, mode)

Using it is equally simple:

.. doctest::

   >>> from zope.security.untrustedpython.rcompile import compile

   >>> code = compile("21 * 2", "<string>", "eval")
   >>> eval(code)
   42

What's interesting about the restricted code is that all attribute
lookups go through the `getattr()` function.  This is generally
provided as a built-in function in the restricted environment:

.. doctest::

   >>> def mygetattr(object, name, default="Yahoo!"):
   ...     marker = []
   ...     print "Looking up", name
   ...     if getattr(object, name, marker) is marker:
   ...         return default
   ...     else:
   ...         return "Yeehaw!"

   >>> import __builtin__
   >>> builtins = __builtin__.__dict__.copy()
   >>> builtins["getattr"] = mygetattr

   >>> def reval(source):
   ...     code = compile(source, "README.txt", "eval")
   ...     globals = {"__builtins__": builtins}
   ...     return eval(code, globals, {})

   >>> reval("(42).__class__")
   Looking up __class__
   'Yeehaw!'
   >>> reval("(42).not_really_there")
   Looking up not_really_there
   'Yahoo!'
   >>> reval("(42).foo.not_really_there")
   Looking up foo
   Looking up not_really_there
   'Yahoo!'

This allows a `getattr()` to be used that ensures the result of
evaluation is a security proxy.

To compile code with statements, use exec or single:

.. doctest::

   >>> exec compile("x = 1", "<string>", "exec")
   >>> x
   1

Trying to compile exec, raise or try/except sattements gives
syntax errors:

.. doctest::

   >>> compile("exec 'x = 2'", "<string>", "exec")
   Traceback (most recent call last):
   ...
   SyntaxError: Line 1: exec statements are not supported

   >>> compile("raise KeyError('x')", "<string>", "exec")
   Traceback (most recent call last):
   ...
   SyntaxError: Line 1: raise statements are not supported

   >>> compile("try: pass\nexcept: pass", "<string>", "exec")
   Traceback (most recent call last):
   ...
   SyntaxError: Line 1: try/except statements are not supported

Printing to an explicit writable is allowed:

.. doctest::

   >>> import StringIO
   >>> f = StringIO.StringIO()
   >>> code = compile("print >> f, 'hi',\nprint >> f, 'world'", '', 'exec')
   >>> exec code in {'f': f}
   >>> f.getvalue()
   'hi world\n'

But if no output is specified, then output will be send to
`untrusted_output`:

.. doctest::

   >>> code = compile("print 'hi',\nprint 'world'", '', 'exec')
   >>> exec code in {}
   Traceback (most recent call last):
   ...
   NameError: name 'untrusted_output' is not defined

   >>> f = StringIO.StringIO()
   >>> exec code in {'untrusted_output': f}
