/*    pywipi.c    */

/*
 * Author: ripmeep
 * GitHub: https://github.com/ripmeep/
 * Date  : 21/03/2023
 */

/*
 * Python3 module wrapper for the wipi C library
 * module - requires python3-dev
 *
 * (Python.h)
 * (structmember.h)
 */

#define _GNU_SOURCE

/*    INCLUDES    */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "wipi.h"
#include "Python.h"
#include "structmember.h"

typedef struct __py_wipi_interface_t
{
    PyObject_HEAD

    PyObject*                   name;
    PyObject*                   addr;
    PyObject*                   mask;
    PyObject*                   flags;
    PyObject*                   monitor_mode;

    struct __wipi_interface_t*  wi;
} py_wipi_interface_t;

typedef struct __py_wipi_scanner_t
{
    PyObject_HEAD

    struct __wipi_scanner_t*    ws;
} py_wipi_scanner_t;

typedef struct __py_wipi_beacon_t
{
    PyObject_HEAD

    PyObject*  ssid;
    PyObject*  bssid;
    PyObject*  stats;
    PyObject*  frequency;
    PyObject*  quality;
    PyObject*  db;
    PyObject*  channel;

    struct __wipi_beacon_t*     wb;
} py_wipi_beacon_t;

static void py_wipi_interface_dealloc(py_wipi_interface_t* self)
{
    wipi_interface_t*   wi;

    Py_XDECREF(self->name);
    Py_XDECREF(self->addr);
    Py_XDECREF(self->mask);
    Py_XDECREF(self->flags);
    Py_XDECREF(self->monitor_mode);

    wi = self->wi->head;

    for (wi = wi; wi->next; wi = wi->next)
        memset( wi, 0, sizeof(wipi_interface_t) );

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* py_wipi_interface_new(PyTypeObject* type, PyObject* args, PyObject* kwds)
{
    py_wipi_interface_t*    self;

    self = (py_wipi_interface_t*)type->tp_alloc(type, 0);

    if (self)
    {
        self->name         = Py_None;
        self->addr         = Py_None;
        self->mask         = Py_None;
        self->flags        = PyLong_FromLong(0);
        self->monitor_mode = Py_False;
    }

    return (PyObject*)self;
}

static int py_wipi_interface_init(py_wipi_interface_t* self, PyObject* args, PyObject* kwds)
{
    Py_INCREF(self->name);
    Py_INCREF(self->addr);
    Py_INCREF(self->mask);
    Py_INCREF(self->flags);
    Py_INCREF(self->monitor_mode);

    return 0;
}

static PyMemberDef py_wipi_interface_members[] = {
    {"name",         T_OBJECT_EX, offsetof(py_wipi_interface_t, name),         READONLY, "The name of the interface"               },
    {"addr",         T_OBJECT_EX, offsetof(py_wipi_interface_t, addr),         READONLY, "The address of the interface"            },
    {"mask",         T_OBJECT_EX, offsetof(py_wipi_interface_t, mask),         READONLY, "The netmask of the interface"            },
    {"flags",        T_OBJECT_EX, offsetof(py_wipi_interface_t, flags),        READONLY, "The ioctl flags currently set"           },
    {"monitor_mode", T_OBJECT_EX, offsetof(py_wipi_interface_t, monitor_mode), READONLY, "The monitor mode status of the interface"},
    {NULL}
};

static PyTypeObject py_wipi_interface_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "wipi.interface",
    .tp_doc       = "Wipi interface object",
    .tp_basicsize = sizeof(py_wipi_interface_t),
    .tp_itemsize  = 0,
    .tp_flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new       = py_wipi_interface_new,
    .tp_init      = (initproc)py_wipi_interface_init,
//  .tp_dealloc   = (destructor)py_wipi_interface_dealloc,
    .tp_members   = py_wipi_interface_members,
};

static void py_wipi_beacon_dealloc(py_wipi_beacon_t* self)
{
    wipi_beacon_t*  wb;

    Py_XDECREF(self->ssid);
    Py_XDECREF(self->bssid);
    Py_XDECREF(self->stats);
    Py_XDECREF(self->frequency);
    Py_XDECREF(self->quality);
    Py_XDECREF(self->db);
    Py_XDECREF(self->channel);

    wb = self->wb->head;

    for (wb = wb; wb->next; wb = wb->next)
        memset( wb, 0, sizeof(wipi_beacon_t) );

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* py_wipi_beacon_new(PyTypeObject* type, PyObject* args, PyObject* kwds)
{
    py_wipi_beacon_t*   self;

    self = (py_wipi_beacon_t*)type->tp_alloc(type, 0);

    if (self)
    {
        self->ssid      = Py_None;
        self->bssid     = Py_None;
        self->stats     = Py_None;
        self->frequency = PyFloat_FromDouble(0.0);
        self->quality   = PyFloat_FromDouble(0.0);
        self->db        = PyLong_FromLong(0);
        self->channel   = PyLong_FromLong(0);
    }

    return (PyObject*)self;
}

static int py_wipi_beacon_init(py_wipi_beacon_t* self, PyObject* args, PyObject* kwds)
{
    Py_INCREF(self->ssid);
    Py_INCREF(self->bssid);
    Py_INCREF(self->stats);
    Py_INCREF(self->frequency);
    Py_INCREF(self->quality);
    Py_INCREF(self->db);
    Py_INCREF(self->channel);

    return 0;
}

static PyObject* py_wipi_beacon_deauth(py_wipi_beacon_t* self, PyObject* args, PyObject* kwds)
{
    py_wipi_interface_t*    py_interface;
    wipi_interface_t        wi;
    char*                   bssid;
    int                     packets, delay, sent;
    PyObject*               py_repr;

    if (!PyArg_ParseTuple(args,
						  "O!ii",
						  &py_wipi_interface_type,
						  &py_interface,
						  &packets,
						  &delay))
	{
		PyErr_SetString(PyExc_TypeError, "Invalid arguments");

		return NULL;
	}

    py_repr = PyObject_Str(self->bssid);
    py_repr = PyUnicode_AsEncodedString(py_repr, "ascii", "~E~");

    bssid = PyBytes_AsString(py_repr);

    py_repr = PyObject_Str(py_interface->name);
    py_repr = PyUnicode_AsEncodedString(py_repr, "ascii", "~E~");

    memset( &wi, 0, sizeof(wi) );
    wi.if_name = strdup( PyBytes_AsString(py_repr) );
    wi.if_mon = py_interface->monitor_mode == Py_True ? 1 : 0;

    sent = wipi_deauth(&wi,
                       bssid,
                       packets,
                       delay);

    return PyLong_FromLong(sent);
}

static PyObject* py_wipi_deauth(PyObject* self, PyObject* args, PyObject* kwds)
{
    PyObject*           py_interface, *py_bssid;
    wipi_interface_t    wi, *wip;
    wipi_beacon_t       wb;
    char*               bssid, *interface;
    int                 packets, delay, sent;

    if (!PyArg_ParseTuple(args,
                          "OOii",
                          &py_interface,
                          &py_bssid,
                          &packets,
                          &delay))
    {
        PyErr_SetString(PyExc_TypeError, "Invalid arguments");

        return NULL;
    }

    py_interface = PyObject_Str(py_interface);
    py_bssid = PyObject_Str(py_bssid);

    if (!py_interface || !py_bssid)
    {
        PyErr_SetString(PyExc_TypeError, "Invalid arguments");

        return NULL;
    }

    py_interface = PyUnicode_AsEncodedString(py_interface, "ascii", "~E~");
    py_bssid = PyUnicode_AsEncodedString(py_bssid, "ascii", "~E~");

    wip = wipi_get_interfaces(17);
    wip = wipi_interface_get( wip, PyBytes_AsString(py_interface) );

    if (!wip)
        return PyLong_FromLong(-1);

    sent = wipi_deauth(wip,
                       PyBytes_AsString(py_bssid),
                       packets,
                       delay);

    return PyLong_FromLong(sent);
}

static PyMemberDef py_wipi_beacon_members[] = {
    {"ssid",         T_OBJECT_EX, offsetof(py_wipi_beacon_t, ssid),         READONLY, "The SSID of the access point beacon"          },
    {"bssid",        T_OBJECT_EX, offsetof(py_wipi_beacon_t, bssid),        READONLY, "The BSSID of the access point beacon"         },
    {"stats",        T_OBJECT_EX, offsetof(py_wipi_beacon_t, stats),        READONLY, "The stats of the access point beacon"         },
    {"frequency",    T_OBJECT_EX, offsetof(py_wipi_beacon_t, frequency),    READONLY, "The frequency of the access point beacon (Hz)"},
    {"quality",      T_OBJECT_EX, offsetof(py_wipi_beacon_t, quality),      READONLY, "The quality % of the access point beacon"     },
    {"db",           T_OBJECT_EX, offsetof(py_wipi_beacon_t, db),           READONLY, "The decibels of the access point beacon (sig)"},
    {"channel",      T_OBJECT_EX, offsetof(py_wipi_beacon_t, channel),      READONLY, "The channel of the access point beacon"       },
    {NULL}
};

static PyMethodDef py_wipi_beacon_methods[] = {
    {"deauth", (PyCFunction)py_wipi_beacon_deauth, METH_VARARGS, "Deauthenticate a specified beacon with a specified interface"},
	{NULL}
};

static PyTypeObject py_wipi_beacon_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "wipi.beacon",
    .tp_doc       = "Wipi beacon object",
    .tp_basicsize = sizeof(py_wipi_beacon_t),
    .tp_itemsize  = 0,
    .tp_flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new       = py_wipi_beacon_new,
    .tp_init      = (initproc)py_wipi_beacon_init,
//  .tp_dealloc   = (destructor)py_wipi_beacon_dealloc,
	.tp_methods   = py_wipi_beacon_methods,
    .tp_members   = py_wipi_beacon_members
};

static void py_wipi_scanner_dealloc(py_wipi_scanner_t* self)
{
    memset( self->ws, 0, sizeof(wipi_scanner_t) );

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* py_wipi_scanner_new(PyTypeObject* type, PyObject* args, PyObject* kwds)
{
    py_wipi_scanner_t*  self;

    self = (py_wipi_scanner_t*)type->tp_alloc(type, 0);

    return (PyObject*)self;
}

static int py_wipi_scanner_init(py_wipi_scanner_t* self, PyObject* args, PyObject* kwds)
{
    PyObject*   py_iface, *py_copy;

    if (!PyArg_ParseTuple(args, "O", &py_iface))
        return -1;

    if (py_iface)
    {
        py_copy = PyObject_Str(py_iface);

        if (!py_copy)
            return -1;

        py_copy = PyUnicode_AsEncodedString(py_copy, "ascii", "~E~");

        self->ws = wipi_scanner_init( (char*)PyBytes_AsString(py_copy) );

        if (!self->ws)
        {
            PyErr_Format( PyExc_RuntimeError, "Failed to initialize wipi scanner - %s", strerror(errno) );
    
            return -1;
        }

        return 0;
    }

    PyErr_SetString(PyExc_RuntimeError, "Could not parse arguments for new scanner");

    return -1;
}

static PyObject* py_wipi_scanner_scan(py_wipi_scanner_t* self, PyObject* Py_UNUSED(ignored))
{
    wipi_beacon_t*      wb;
    PyObject*           py_list;
    py_wipi_beacon_t*   py_beacon;

    py_list = PyList_New(0);

    wb = wipi_scanner_scan(self->ws);

    if (!wb)
    {
        PyErr_Format( PyExc_RuntimeError, "Scan failed - %s", strerror(errno) );

        return NULL;
    }

    for (wb = wb; wb->next; wb = wb->next)
    {
        py_beacon = (py_wipi_beacon_t*)py_wipi_beacon_new(&py_wipi_beacon_type, NULL, NULL);
        py_wipi_beacon_init(py_beacon, NULL, NULL);

		py_beacon->ssid      = PyUnicode_FromString(wb->ssid);
		py_beacon->bssid     = PyUnicode_FromString(wb->bssid);
        py_beacon->stats     = PyUnicode_FromString(wb->stats);
        py_beacon->frequency = PyFloat_FromDouble(wb->freq);
        py_beacon->quality   = PyFloat_FromDouble((double)wb->qual);
        py_beacon->db        = PyLong_FromLong((long)wb->channel);

        PyList_Append(py_list, (PyObject*)py_beacon);
    }

    return py_list;
}

static PyMemberDef py_wipi_scanner_members[] = {
    {"interface", T_STRING, offsetof(py_wipi_scanner_t, ws) + offsetof(wipi_scanner_t, iface),  0, "The interface being used for beacon scanning"},
    {"status",    T_INT,    offsetof(py_wipi_scanner_t, ws) + offsetof(wipi_scanner_t, status), 0, "The current status of the scanner"           },
    {NULL}
};

static PyMethodDef py_wipi_scanner_methods[] = {
    {"scan", (PyCFunction)py_wipi_scanner_scan, METH_NOARGS, "Scan for nearby access point beacons"},
    {NULL}
};

static PyTypeObject py_wipi_scanner_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "wipi.scanner",
    .tp_doc       = "Wipi scanner object",
    .tp_basicsize = sizeof(py_wipi_scanner_t),
    .tp_itemsize  = 0,
    .tp_flags     = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new       = py_wipi_scanner_new,
    .tp_init      = (initproc)py_wipi_scanner_init,
//  .tp_dealloc   = (destructor)py_wipi_scanner_dealloc,
    .tp_members   = py_wipi_scanner_members,
    .tp_methods   = py_wipi_scanner_methods,
};

static PyObject* py_wipi_get_interfaces(PyObject* self, PyObject* args, PyObject* kwds)
{
    int                     sa_family;
    wipi_interface_t*       wi;
    PyObject*               py_sa_family, *py_list;
    py_wipi_interface_t*    py_interface;

    if (!PyArg_ParseTuple(args, "O", &py_sa_family))
    {
        PyErr_SetString(PyExc_Exception, "Integer parameter required");

        return NULL;
    }

    sa_family = PyLong_AsLong(py_sa_family);

    py_list = PyList_New(0);

    wi = wipi_get_interfaces(sa_family);

    for (wi = wi; wi->next; wi = wi->next)
    {
        py_interface = (py_wipi_interface_t*)py_wipi_interface_new(&py_wipi_interface_type, NULL, NULL);
        py_wipi_interface_init(py_interface, NULL, NULL);

        py_interface->name         = PyUnicode_FromString(wi->if_name);
        py_interface->addr         = PyUnicode_FromString(wi->if_addr);
        py_interface->mask         = PyUnicode_FromString(wi->if_mask);
        py_interface->flags        = PyLong_FromLong(wi->if_flags);
        py_interface->monitor_mode = wi->if_mon ? Py_True : Py_False;

        PyList_Append(py_list, (PyObject*)py_interface);
    }

    return py_list;
}

static PyMethodDef py_wipi_methods[] = {
    {"get_interfaces", (PyCFunction)py_wipi_get_interfaces, METH_VARARGS, "List current network interfaces with specified SA family type"},
    {"deauth",         (PyCFunction)py_wipi_deauth,         METH_VARARGS, "Deauth a BSSID from the root module"},
    {NULL}
};

static PyModuleDef wipi_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "wipi",
    .m_doc = "A python3 module wrapper for the wipi C library",
    .m_size = -1,
    .m_methods = py_wipi_methods, 
};

PyMODINIT_FUNC PyInit_wipi(void)
{
    PyObject*   m;

    if (PyType_Ready(&py_wipi_scanner_type) < 0 ||
        PyType_Ready(&py_wipi_beacon_type) < 0 ||
        PyType_Ready(&py_wipi_interface_type) < 0)
        return NULL;

    m = PyModule_Create(&wipi_module);

    if (m == NULL)
        return NULL;

    Py_INCREF(&py_wipi_scanner_type);
    Py_INCREF(&py_wipi_beacon_type);
    Py_INCREF(&py_wipi_interface_type);

    if (PyModule_AddObject(m, "scanner", (PyObject*)&py_wipi_scanner_type) < 0 ||
        PyModule_AddObject(m, "beacon", (PyObject*)&py_wipi_beacon_type) < 0 ||
        PyModule_AddObject(m, "interface", (PyObject*)&py_wipi_interface_type) < 0)
    {
        Py_DECREF(&py_wipi_scanner_type);
        Py_DECREF(&py_wipi_beacon_type);
        Py_DECREF(&py_wipi_interface_type);
        Py_DECREF(m);

        return NULL;
    }

    return m;
}
