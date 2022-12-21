/*

 Copyright (c) 2004 Zope Foundation and Contributors.
 All Rights Reserved.

 This software is subject to the provisions of the Zope Public License,
 Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
 THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
 WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
 FOR A PARTICULAR PURPOSE.

*/
#include <Python.h>

static PyObject *_checkers, *_defaultChecker, *_available_by_default, *NoProxy;
static PyObject *Proxy, *thread_local, *CheckerPublic;
static PyObject *ForbiddenAttribute, *Unauthorized;


#define PyInt_FromLong PyLong_FromLong

#define IS_STRING PyUnicode_Check

#define MAKE_STRING(name) PyBytes_AS_STRING( \
        PyUnicode_AsUTF8String(name))

#define FROM_STRING PyUnicode_FromString

#define FROM_STRING_FORMAT PyUnicode_FromFormat

#define INTERN PyUnicode_InternFromString

#define MOD_ERROR_VAL NULL

#define MOD_SUCCESS_VAL(val) val

#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)

#define MOD_DEF(ob, name, doc, methods) \
        static struct PyModuleDef moduledef = { \
          PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
        ob = PyModule_Create(&moduledef);

#define statichere static

#define DECLARE_STRING(N) static PyObject *str_##N

DECLARE_STRING(checkPermission);
DECLARE_STRING(__Security_checker__);
DECLARE_STRING(interaction);

#define CLEAR(O) if (O) {PyObject *t = O; O = 0; Py_DECREF(t); }

typedef struct {
    PyObject_HEAD
        PyObject *getperms, *setperms;
} Checker;

/*     def permission_id(self, name): */
static PyObject *
Checker_permission_id(Checker *self, PyObject *name)
{
/*         return self._permission_func(name) */
  PyObject *result;

  if (self->getperms)
    {
      result = PyDict_GetItem(self->getperms, name);
      if (result == NULL)
        result = Py_None;
    }
  else
    result = Py_None;

  Py_INCREF(result);
  return result;
}

/*     def setattr_permission_id(self, name): */
static PyObject *
Checker_setattr_permission_id(Checker *self, PyObject *name)
{
/*         return self._setattr_permission_func(name) */
  PyObject *result;

  if (self->setperms)
    {
      result = PyDict_GetItem(self->setperms, name);
      if (result == NULL)
        result = Py_None;
    }
  else
    result = Py_None;

  Py_INCREF(result);
  return result;
}

static int
checkPermission(PyObject *permission, PyObject *object, PyObject *name)
{
      PyObject *interaction, *r;
      int i;

/*          if thread_local.interaction.checkPermission(permission, object): */
/*                 return */
      interaction = PyObject_GetAttr(thread_local, str_interaction);
      if (interaction == NULL)
        return -1;
      r = PyObject_CallMethodObjArgs(interaction, str_checkPermission,
                                     permission, object, NULL);
      Py_DECREF(interaction);
      if (r == NULL)
        return -1;
      i = PyObject_IsTrue(r);
      Py_DECREF(r);
      if (i < 0)
        return -1;
      if (i)
        return 0;
/*             else: */
/*                 __traceback_supplement__ = (TracebackSupplement, object) */
/*                 raise Unauthorized(object, name, permission) */
      r = Py_BuildValue("OOO", object, name, permission);
      if (r == NULL)
        return -1;
      PyErr_SetObject(Unauthorized, r);
      Py_DECREF(r);
      return -1;
}


/*     def check(self, object, name): */

/* Note that we have an int version here because we will use it for
   __setitem__, as described below */

static int
Checker_check_int(Checker *self, PyObject *object, PyObject *name)
{
  PyObject *permission=NULL;
  int operator;

/*         permission = self._permission_func(name) */
  if (self->getperms)
    permission = PyDict_GetItem(self->getperms, name);

/*         if permission is not None: */
  if (permission != NULL)
    {
/*             if permission is CheckerPublic: */
/*                 return # Public */
      if (permission == CheckerPublic)
        return 0;

      if (checkPermission(permission, object, name) < 0)
        return -1;
      return 0;
    }


  operator = (IS_STRING(name)
              && MAKE_STRING(name)[0] == '_'
              && MAKE_STRING(name)[1] == '_');

  if (operator)
    {
/*         elif name in _available_by_default: */
/*             return */
      int ic = PySequence_Contains(_available_by_default, name);
      if (ic < 0)
        return -1;
      if (ic)
        return 0;

/*         if name != '__iter__' or hasattr(object, name): */
/*             __traceback_supplement__ = (TracebackSupplement, object) */
/*             raise ForbiddenAttribute, (name, object) */

      if (strcmp("__iter__", MAKE_STRING(name)) == 0
          && ! PyObject_HasAttr(object, name))
        /* We want an attr error if we're asked for __iter__ and we don't
           have it. We'll get one by allowing the access. */
        return 0;
    }

  {
    PyObject *args;
    args = Py_BuildValue("OO", name, object);
    if (args != NULL)
      {
        PyErr_SetObject(ForbiddenAttribute, args);
        Py_DECREF(args);
      }
    return -1;
  }
}

/* Here we have the non-int version, implemented using the int
   version, which is exposed as a method */

static PyObject *
Checker_check(Checker *self, PyObject *args)
{
  PyObject *object, *name;

  if (!PyArg_ParseTuple(args, "OO", &object, &name))
    return NULL;

  if (Checker_check_int(self, object, name) < 0)
    return NULL;

  Py_INCREF(Py_None);
  return Py_None;
}


/*     def check_setattr(self, object, name): */
static PyObject *
Checker_check_setattr(Checker *self, PyObject *args)
{
  PyObject *object, *name, *permission=NULL;

  if (!PyArg_ParseTuple(args, "OO", &object, &name))
    return NULL;

/*         permission = self._permission_func(name) */
  if (self->setperms)
    permission = PyDict_GetItem(self->setperms, name);

/*         if permission is not None: */
  if (permission != NULL)
    {
/*             if permission is CheckerPublic: */
/*                 return # Public */
      if (permission != CheckerPublic
          && checkPermission(permission, object, name) < 0)
        return NULL;

      Py_INCREF(Py_None);
      return Py_None;
    }

/*         __traceback_supplement__ = (TracebackSupplement, object) */
/*         raise ForbiddenAttribute, (name, object) */
  args = Py_BuildValue("OO", name, object);
  if (args != NULL)
    {
      PyErr_SetObject(ForbiddenAttribute, args);
      Py_DECREF(args);
    }
  return NULL;
}


static PyObject *
selectChecker(PyObject *ignored, PyObject *object);

/*     def proxy(self, value): */
static PyObject *
Checker_proxy(Checker *self, PyObject *value)
{
  PyObject *checker, *r;

/*        if type(value) is Proxy: */
/*            return value */
  if ((PyObject*)Py_TYPE(value) == Proxy)
    {
      Py_INCREF(value);
      return value;
    }

/*         checker = getattr(value, '__Security_checker__', None) */
  checker = PyObject_GetAttr(value, str___Security_checker__);
/*         if checker is None: */
  if (checker == NULL)
    {
      PyErr_Clear();

/*             checker = selectChecker(value) */
      checker = selectChecker(NULL, value);
      if (checker == NULL)
        return NULL;

/*             if checker is None: */
/*                 return value */
      if (checker == Py_None)
        {
          Py_DECREF(checker);
          Py_INCREF(value);
          return value;
        }
    }
  else if (checker == Py_None)
    {
      PyObject *errv = Py_BuildValue("sO",
                                     "Invalid value, None. "
                                     "for security checker",
                                     value);
      if (errv != NULL)
        {
          PyErr_SetObject(PyExc_ValueError, errv);
          Py_DECREF(errv);
        }

      return NULL;
    }

  r = PyObject_CallFunctionObjArgs(Proxy, value, checker, NULL);
  Py_DECREF(checker);
  return r;
}

/*         return Proxy(value, checker) */


static struct PyMethodDef Checker_methods[] = {
  {"permission_id", (PyCFunction)Checker_permission_id, METH_O,
   "permission_id(name) -- Return the permission neded to get the name"},
  {"setattr_permission_id", (PyCFunction)Checker_setattr_permission_id,
   METH_O,
   "setattr_permission_id(name) -- Return the permission neded to set the name"
  },
  {"check_getattr", (PyCFunction)Checker_check, METH_VARARGS,
   "check_getattr(object, name) -- Check whether a getattr is allowed"},
  {"check_setattr", (PyCFunction)Checker_check_setattr, METH_VARARGS,
   "check_setattr(object, name) -- Check whether a setattr is allowed"},
  {"check", (PyCFunction)Checker_check, METH_VARARGS,
   "check(object, opname) -- Check whether an operation is allowed"},
  {"proxy", (PyCFunction)Checker_proxy, METH_O,
   "proxy(object) -- Security-proxy an object"},

  {NULL,  NULL}     /* sentinel */
};

static int
Checker_clear(Checker *self)
{
  CLEAR(self->getperms);
  CLEAR(self->setperms);
  return 0;
}

static void
Checker_dealloc(Checker *self)
{
  PyObject_GC_UnTrack((PyObject*)self);
  Checker_clear(self);
  Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
Checker_traverse(Checker *self, visitproc visit, void *arg)
{
  if (self->getperms != NULL && visit(self->getperms, arg) < 0)
    return -1;
  if (self->setperms != NULL && visit(self->setperms, arg) < 0)
    return -1;

  return 0;
}

static int
Checker_init(Checker *self, PyObject *args, PyObject *kwds)
{
  PyObject *getperms, *setperms=NULL;
  static char *kwlist[] = {"get_permissions", "set_permissions", NULL};

  if (! PyArg_ParseTupleAndKeywords(args, kwds, "O!|O!:Checker", kwlist,
                                    &PyDict_Type, &getperms,
                                    &PyDict_Type, &setperms))
    return -1;

  Py_INCREF(getperms);
  self->getperms = getperms;
  Py_XINCREF(setperms);
  self->setperms = setperms;

  return 0;
}

static PyObject *
Checker_get_get_permissions(Checker *self, void *closure)
{
  if (self->getperms == NULL)
    {
      self->getperms = PyDict_New();
      if (self->getperms == NULL)
        return NULL;
    }

  Py_INCREF(self->getperms);
  return self->getperms;
}

static PyObject *
Checker_get_set_permissions(Checker *self, void *closure)
{
  if (self->setperms == NULL)
    {
      self->setperms = PyDict_New();
      if (self->setperms == NULL)
        return NULL;
    }

  Py_INCREF(self->setperms);
  return self->setperms;
}

static PyGetSetDef Checker_getset[] = {
    {"get_permissions",
     (getter)Checker_get_get_permissions, NULL,
     "getattr name to permission dictionary",
     NULL},
    {"set_permissions",
     (getter)Checker_get_set_permissions, NULL,
     "setattr name to permission dictionary",
     NULL},
    {NULL}  /* Sentinel */
};

/* We create operator aliases for check and proxy. Why? Because
   calling operator slots is much faster than calling methods and
   security checks are done so often that speed matters.  So we have
   this hack of using almost-arbitrary operations to represent methods
   that we call alot.  The security proxy implementation participates
   in the same hack. */

static PyMappingMethods Checker_as_mapping = {
    /* mp_length        */ NULL,
    /* mp_subscript     */ (binaryfunc)Checker_proxy,
    /* mp_ass_subscript */ (objobjargproc)Checker_check_int,
};



static PyTypeObject CheckerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "zope.security.checker.Checker",
    sizeof(Checker),
    0,                                  /* tp_itemsize       */
    (destructor)&Checker_dealloc,       /* tp_dealloc        */
    0,                                  /* tp_print          */
    0,                                  /* tp_getattr        */
    0,                                  /* tp_setattr        */
    0,                                  /* tp_compare        */
    0,                                  /* tp_repr           */
    0,                                  /* tp_as_number      */
    0,                                  /* tp_as_sequence    */
    &Checker_as_mapping,                /* tp_as_mapping     */
    0,                                  /* tp_hash           */
    0,                                  /* tp_call           */
    0,                                  /* tp_str            */
    0,                                  /* tp_getattro       */
    0,                                  /* tp_setattro       */
    0,                                  /* tp_as_buffer      */
    Py_TPFLAGS_DEFAULT |
    Py_TPFLAGS_BASETYPE |
    Py_TPFLAGS_HAVE_GC,                 /* tp_flags          */
    "Security checker",                 /* tp_doc            */
    (traverseproc)Checker_traverse,     /* tp_traverse       */
    (inquiry)Checker_clear,             /* tp_clear          */
    0,                                  /* tp_richcompare    */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter           */
    0,                                  /* tp_iternext       */
    Checker_methods,                    /* tp_methods        */
    0,                                  /* tp_members        */
    Checker_getset,                     /* tp_getset         */
    0,                                  /* tp_base           */
    0, /* internal use */               /* tp_dict           */
    0,                                  /* tp_descr_get      */
    0,                                  /* tp_descr_set      */
    0,                                  /* tp_dictoffset     */
    (initproc)Checker_init,             /* tp_init           */
    0,                                  /* tp_alloc          */
    0,                                  /* tp_new            */
    0, /* Low-level free-mem routine */ /* tp_free           */
    0, /* For PyObject_IS_GC */         /* tp_is_gc          */
};





/* def selectChecker(object): */
/*     """Get a checker for the given object */
/*     The appropriate checker is returned or None is returned. If the */
/*     return value is None, then object should not be wrapped in a proxy. */
/*     """ */

static char selectChecker_doc[] =
"Get a checker for the given object\n"
"\n"
"The appropriate checker is returned or None is returned. If the\n"
"return value is None, then object should not be wrapped in a proxy.\n"
;

static PyObject *
selectChecker(PyObject *ignored, PyObject *object)
{
  PyObject *checker;

/*     checker = _getChecker(type(object), _defaultChecker) */

  checker = PyDict_GetItem(_checkers, (PyObject*)Py_TYPE(object));
  if (checker == NULL)
    checker = _defaultChecker;

/*     if checker is NoProxy: */
/*         return None */

  if (checker == NoProxy)
    {
      Py_INCREF(Py_None);
      return Py_None;
    }

/*     if checker is _defaultChecker and isinstance(object, Exception): */
/*         return None */

  if (checker == _defaultChecker
      && PyObject_IsInstance(object, PyExc_Exception))
    {
      Py_INCREF(Py_None);
      return Py_None;
    }

/*     while not isinstance(checker, Checker): */
/*         checker = checker(object) */
/*         if checker is NoProxy or checker is None: */
/*             return None */

  Py_INCREF(checker);
  while (! PyObject_TypeCheck(checker, &CheckerType))
    {
      PyObject *newchecker;
      newchecker = PyObject_CallFunctionObjArgs(checker, object, NULL);
      Py_DECREF(checker);
      if (newchecker == NULL)
        return NULL;
      checker = newchecker;
      if (checker == NoProxy || checker == Py_None)
        {
          Py_DECREF(checker);
          Py_INCREF(Py_None);
          return Py_None;
        }
    }

/*     return checker */

  return checker;
}

static char
module___doc__[] = "C optimizations for zope.security.checker";


static PyMethodDef
module_functions[] = {
  {"selectChecker", (PyCFunction)selectChecker, METH_O, selectChecker_doc},
  {NULL}  /* Sentinel */
};

MOD_INIT(_zope_security_checker)
{
  PyObject* m;
  PyObject* mod;

  MOD_DEF(mod, "_zope_security_checker", module___doc__, module_functions)

  if (mod == NULL)
  {
    return MOD_ERROR_VAL;
  }

  CheckerType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&CheckerType) < 0)
  {
    return MOD_ERROR_VAL;
  }

  _defaultChecker = PyObject_CallFunction((PyObject*)&CheckerType, "{}");
  if (_defaultChecker == NULL)
  {
    return MOD_ERROR_VAL;
  }

#define INIT_STRING(S) \
if((str_##S = INTERN(#S)) == NULL) return MOD_ERROR_VAL

  INIT_STRING(checkPermission);
  INIT_STRING(__Security_checker__);
  INIT_STRING(interaction);

  if ((_checkers = PyDict_New()) == NULL)
  {
    return MOD_ERROR_VAL;
  }

  NoProxy = PyObject_CallObject((PyObject*)&PyBaseObject_Type, NULL);
  if (NoProxy == NULL)
  {
    return MOD_ERROR_VAL;
  }

  if ((m = PyImport_ImportModule("zope.security._proxy")) == NULL)
  {
    return MOD_ERROR_VAL;
  }
  if ((Proxy = PyObject_GetAttrString(m, "_Proxy")) == NULL)
  {
    return MOD_ERROR_VAL;
  }
  Py_DECREF(m);

  if ((m = PyImport_ImportModule("zope.security._definitions")) == NULL)
  {
    return MOD_ERROR_VAL;
  }
  thread_local = PyObject_GetAttrString(m, "thread_local");
  if (thread_local == NULL)
  {
    return MOD_ERROR_VAL;
  }
  Py_DECREF(m);

  if ((m = PyImport_ImportModule("zope.security.interfaces")) == NULL)
  {
    return MOD_ERROR_VAL;
  }
  ForbiddenAttribute = PyObject_GetAttrString(m, "ForbiddenAttribute");
  if (ForbiddenAttribute == NULL)
  {
    return MOD_ERROR_VAL;
  }
  Unauthorized = PyObject_GetAttrString(m, "Unauthorized");
  if (Unauthorized == NULL)
  {
    return MOD_ERROR_VAL;
  }
  Py_DECREF(m);

  if ((m = PyImport_ImportModule("zope.security.checker")) == NULL)
  {
    return MOD_ERROR_VAL;
  }
  CheckerPublic = PyObject_GetAttrString(m, "CheckerPublic");
  if (CheckerPublic == NULL)
  {
    return MOD_ERROR_VAL;
  }
  Py_DECREF(m);

  if ((_available_by_default = PyList_New(0)) == NULL)
  {
    return MOD_ERROR_VAL;
  }

#define EXPORT(N) Py_INCREF(N); PyModule_AddObject(mod, #N, N)

  EXPORT(_checkers);
  EXPORT(NoProxy);
  EXPORT(_defaultChecker);
  EXPORT(_available_by_default);

  Py_INCREF(&CheckerType);
  PyModule_AddObject(mod, "Checker", (PyObject *)&CheckerType);

  return MOD_SUCCESS_VAL(mod);
}
