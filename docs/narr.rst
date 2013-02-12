Overview
========

Introduction
------------

The Security framework provides a generic mechanism to implement security
policies on Python objects.  This introduction provides a tutorial of the
framework explaining concepts, design, and going through sample usage from the
perspective of a Python programmer using the framework outside of Zope.

Definitions
-----------

Principal
~~~~~~~~~

A generalization of a concept of a user.

Permission
~~~~~~~~~~

A kind of access, i.e. permission to READ vs. permission to WRITE.
Fundamentally the whole security framework is organized around checking
permissions on objects.

Purpose
-------

The security framework's primary purpose is to guard and check access to
Python objects.  It does this by providing mechanisms for explicit and
implicit security checks on attribute access for objects.  Attribute names are
mapped onto permission names when checking access and the implementation of
the security check is defined by the security policy, which receives the
object, the permission name, and an interaction.

Interactions are objects that represent the use of the system by one or more
principals.  An interaction contains a list of participations, which
represents the way a single principal participates in the interaction.  An
HTTP request is one example of a participation.

Its important to keep in mind that the policy provided is just a default, and
it can be substituted with one which doesn't care about principals or
interactions at all.

Framework Components
--------------------

Low Level Components
~~~~~~~~~~~~~~~~~~~~

These components provide the infrastructure for guarding attribute access and
providing hooks into the higher level security framework.

Checkers
~~~~~~~~

A checker is associated with an object kind, and provides the hooks that map
attribute checks onto permissions deferring to the security manager (which in
turn defers to the policy) to perform the check.

Additionally, checkers provide for creating proxies of objects associated with
the checker.

There are several implementation variants of checkers, such as checkers that
grant access based on attribute names.

Proxies
~~~~~~~

Wrappers around Python objects that implicitly guard access to their wrapped
contents by delegating to their associated checker.  Proxies are also viral in
nature, in that values returned by proxies are also proxied.

High Level Components
---------------------

Security Management
~~~~~~~~~~~~~~~~~~~

Provides accessors for setting up interactions and the global security policy.

Interaction
~~~~~~~~~~~

Stores transient information on the list of participations.

Participation
~~~~~~~~~~~~~

Stores information about a principal participating in the interaction.

Security Policy
~~~~~~~~~~~~~~~

Provides a single method that accepts the object, the permission, and the
interaction of the access being checked and is used to implement the
application logic for the security framework.

Narrative (agent sandbox)
-------------------------

As an example we take a look at constructing a multi-agent distributed system,
and then adding a security layer using the Zope security model onto it.

Scenario
~~~~~~~~

Our agent simulation consists of autonomous agents that live in various agent
homes/sandboxes and perform actions that access services available at their
current home.  Agents carry around authentication tokens which signify their
level of access within any given home.  Additionally agents attempt to migrate
from home to home randomly.

The agent simulation was constructed separately from any security aspects.
Now we want to define and integrate a security model into the simulation.  The
full code for the simulation and the security model is available separately;
we present only relevant code snippets here for illustration as we go through
the implementation process.

For the agent simulation we want to add a security model such that we group
agents into two authentication groups, "norse legends", including the
principals thor, odin, and loki, and "greek men", including prometheus,
archimedes, and thucydides.

We associate permissions with access to services and homes.  We differentiate
the homes such that certain authentication groups only have access to services
or the home itself based on the local settings of the home in which they
reside.

We define the homes/sandboxes

  - origin - all agents start here, and have access to all
    services here.

  - valhalla - only agents in the authentication group 'norse
    legend' can reside here.

  - jail - all agents can come here, but only 'norse legend's
    can leave or access services.


Process
~~~~~~~

Loosely we define a process for implementing this security model

  - mapping permissions onto actions

  - mapping authentication tokens onto permissions

  - implementing checkers and security policies that use our
    authentication tokens and permissions.

  - binding checkers to our simulation classes

  - inserting the hooks into the original simulation code to add
    proxy wrappers to automatically check security.

  - inserting hooks into the original simulation to register the
    agents as the active principal in an interaction.


Defining a Permission Model
~~~~~~~~~~~~~~~~~~~~~~~~~~~

We define the following permissions::

   NotAllowed = 'Not Allowed'
   Public = Checker.CheckerPublic
   TransportAgent = 'Transport Agent'
   AccessServices = 'Access Services'
   AccessAgents = 'Access Agents'
   AccessTimeService = 'Access Time Services'
   AccessAgentService = 'Access Agent Service'
   AccessHomeService = 'Access Home Service'

and create a dictionary database mapping homes to authentication groups which
are linked to associated permissions.


Defining and Binding Checkers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Checkers are the foundational unit for the security framework.  They define
what attributes can be accessed or set on a given instance.  They can be used
implicitly via Proxy objects, to guard all attribute access automatically or
explicitly to check a given access for an operation.

Checker construction expects two functions or dictionaries, one is used to map
attribute names to permissions for attribute access and another to do the same
for setting attributes.

We use the following checker factory function::

   def PermissionMapChecker(permissions_map={},
                            setattr_permission_func=NoSetAttr):
       res = {}
       for k,v in permissions_map.items():
           for iv in v:
               res[iv]=k
       return checker.Checker(res.get, setattr_permission_func)

   time_service_checker = PermissionMapChecker(
                                  # permission : [methods]
                                  {'AccessTimeService':['getTime']}
                                  )

with the NoSetAttr function defined as a lambda which always return the
permission `NotAllowed`.

To bind the checkers to the simulation classes we register our checkers with
the security model's global checker registry::

   import sandbox_simulation
   from zope.security.checker import defineChecker
   defineChecker(sandbox_simulation.TimeService, time_service_checker)


Defining a Security Policy
~~~~~~~~~~~~~~~~~~~~~~~~~~

We implement our security policy such that it checks the current agent's
authentication token against the given permission in the home of the object
being accessed::

  @implementer(ISecurityPolicy)
  class SimulationSecurityPolicy:

      createInteraction = staticmethod(simpleinteraction.createInteraction)

      def checkPermission(self, permission, object, interaction):

          home = object.getHome()
          db = getattr(SimulationSecurityDatabase, home.getId(), None)

          if db is None:
              return False

          allowed = db.get('any', ())
          if permission in allowed or ALL in allowed:
              return True

          if interaction is None:
              return False
          if not interaction.participations:
              return False
          for participation in interaction.participations:
              token = participation.principal.getAuthenticationToken()
              allowed = db.get(token, ())
              if permission not in allowed:
                  return False

          return True

There are no specific requirements for the interaction class, so we can just
use `zope.security.simpleinteraction.Interaction`.

Since an interaction can have more than one principal, we check that *all* of
them are given the necessary permission.  This is not really necessary since
we only create interactions with a single active principal.

There is some additional code present to allow for shortcuts in defining the
permission database when defining permissions for all auth groups and all
permissions.


Integration
~~~~~~~~~~~

At this point we have implemented our security model, and we need to integrate
it with our simulation model.  We do so in three separate steps.

First we make it such that agents only access homes that are wrapped in a
security proxy.  By doing this all access to homes and services (proxies have
proxied return values for their methods) is implicitly guarded by our security
policy.

The second step is that we want to associate the active agent with the
security context so the security policy will know which agent's authentication
token to validate against.

The third step is to set our security policy as the default policy for the
Zope security framework.  It is possible to create custom security policies at
a finer grained than global, but such is left as an exercise for the reader.


Interaction Access
~~~~~~~~~~~~~~~~~~

The *default* implementation of the interaction management interfaces defines
interactions on a per thread basis with a function for an accessor.  This
model is not appropriate for all systems, as it restricts one to a single
active interaction per thread at any given moment.  Reimplementing the
interaction access methods though is easily doable and is noted here for
completeness.


Perspectives
~~~~~~~~~~~~

It's important to keep in mind that there is a lot more that is possible using
the security framework than what's been presented here.  All of the
interactions are interface based, such that if you need to re-implement the
semantics to suite your application a new implementation of the interface will
be sufficient.  Additional possibilities range from restricted interpreters
and dynamic loading of untrusted code to non Zope web application security
systems.  Insert imagination here ;-).


Zope Perspective
~~~~~~~~~~~~~~~~

A Zope3 programmer will never commonly need to interact with the low level
security framework.  Zope3 defines a second security package over top the low
level framework and authentication sources and checkers are handled via zcml
registration.  Still those developing Zope3 will hopefully find this useful as
an introduction into the underpinnings of the security framework.


Code
~~~~

The complete code for this example is available.

- sandbox.py - the agent framework

- sandbox_security.py - the security implementation and binding to the agent
  framework.


Authors
~~~~~~~

- Kapil Thangavelu <hazmat at objectrealms.net>
- Guido Wesdorp <guido at infrae.com>
- Marius Gedminas <marius at pov.lt>


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
