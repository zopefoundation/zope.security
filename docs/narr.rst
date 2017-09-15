===========================
 Overview and Introduction
===========================

.. currentmodule:: zope.security.interfaces

The Security framework provides a generic mechanism to implement security
policies on Python objects.  This introduction provides a tutorial of the
framework explaining concepts, design, and going through sample usage from the
perspective of a Python programmer using the framework outside of Zope.

Definitions
===========

Principal
---------

A generalization of a concept of a :class:`user <IPrincipal>`. Further
specializations include :class:`groups of users <IGroup>` and
principals that :class:`know what groups they belong to
<IGroupAwarePrincipal>`. All of these principals may interact with the system.

Permission
----------

A kind of access, i.e. permission to READ vs. permission to WRITE.
Fundamentally the whole security framework is organized around
checking permissions on objects. Permissions are represented (and
checked) as strings, with the exception of :data:`a constant
<zope.security.checker.CheckerPublic>` that has the special meaning of
"public", i.e., no checking needs to be done.

There are :class:`permission objects <IPermission>` that can be
registered as zope.component utilities for validation, introspection,
and producing :func:`lists of available permissions
<zope.security.permission.PermissionVocabulary>` to help users assign
them to objects.

Purpose
=======

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
====================

Low Level Components
--------------------

These components provide the infrastructure for guarding attribute access and
providing hooks into the higher level security framework.

Checkers
~~~~~~~~

A :class:`checker <IChecker>` is associated
with an object kind, and provides the hooks that map attribute checks
onto permissions deferring to the security manager (which in turn
defers to the policy) to perform the check.

Additionally, checkers provide for creating proxies of objects associated with
the checker.

There are several implementation variants of checkers, such as checkers that
grant access based on attribute names.

Proxies
~~~~~~~

:class:`Wrappers around Python objects <zope.security.proxy.Proxy>`
that implicitly guard access to their wrapped contents by delegating
to their associated checker. Proxies are also viral in nature, in that
values returned by proxies are also proxied.

High Level Components
=====================

Security Management
-------------------

Provides accessors for :class:`setting up interactions
<IInteractionManagement>` and the :class:`global security policy
<ISecurityManagement>`.

:class:`Interaction <zope.security.interfaces.IInteraction>`
------------------------------------------------------------

An :class:`interaction <IInteraction>` represents zero or more
principals manipulating or viewing (interacting with) the system.

Interactions also provide :func:`a single method
<IInteraction.checkPermission>` that accepts the object and the
permission of the access being checked and is used to implement the
application logic for the security framework.

Participation
-------------

Stores information about a single principal :class:`participating
<zope.security.interfaces.IParticipation>` in the :class:`interaction
<zope.security.interfaces.IInteraction>`.

Security Policy
---------------

A :class:`security policy <ISecurityPolicy>` is used to create the
interaction that will ultimately be responsible for security checking.
