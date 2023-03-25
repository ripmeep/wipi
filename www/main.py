#!/usr/bin/env python3

import wipi, os, re, time, multiprocessing
from wiapi import wiapi, Request
from wiapi.auth import WiapiJWT, wraps, auth_required as wiapi_auth_required
from wiapi.models import *
from wiapi.db import *
from wiapi.exceptions import WiapiHTTPException

def wiapi_verify_interface(func):
    @wraps(func)

    async def wrapper(*args, **kwargs):
        try:
            interface = kwargs[list(filter(lambda i: type(kwargs[i]) == WiapiInterface or type(kwargs[i]) == WiapiDeauth, kwargs.keys()))[0]]

            ifaces = wipi.get_interfaces(17)

            if interface.interface not in [iface.name for iface in ifaces]:
                raise WiapiHTTPException(
                    status_code=400,
                    detail='Interface does not exist'
                )
        except WiapiHTTPException as e:
            raise e
        except Exception as e:
            raise WiapiHTTPException(
                status_code=400,
                detail="Invalid interface ({})".format(str(e))
            )

        return await func(*args, **kwargs)

    return wrapper

@wiapi.get('/')
async def _root(request: Request):
    return WiapiResponse(
        success=True,
        data={ 'message': 'Wipi - created by ripmeep' }
    )

@wiapi.post('/auth')
async def _login(request: Request, login: WiapiCredentials) -> WiapiResponse:
    db = WiapiDatabase()

    success, user = db.check_credentials(login.username, login.password)

    if not success:
        raise WiapiHTTPException(
            status_code=401,
            detail='Invalid username or password'
        )

    id, username, _, admin = user

    wjwt = WiapiJWT()
    token = wjwt.create_token(username, admin=bool(admin))

    return WiapiResponse(
        success=True,
        data={ 'message': 'Authenticated', 'access_token': token }
    )

@wiapi.get('/whoami')
@wiapi_auth_required
async def _whoami(request: Request) -> WiapiResponse:
    wjwt = WiapiJWT()
    raw_token = wjwt.parse(request.headers['Authorization'].split('Bearer ')[1])

    return WiapiResponse(
        success=True,
        data={ 'message': raw_token }
    )

@wiapi.get('/interfaces')
@wiapi_auth_required
async def _interfaces(request: Request) -> WiapiResponse:
    sa_family = 2

    con_ifaces = wipi.get_interfaces(sa_family) # AF_INET

    sa_family = 17

    ifaces = wipi.get_interfaces(sa_family) # AF_PACKET
    iface_list = [
        {
            iface.name: {
                'addr': iface.addr if not iface.addr.endswith('.0') else None,
                'mask': iface.mask if not iface.mask == "" else None,
                'flags': iface.flags,
                'monitor_mode': iface.monitor_mode
            }
        }

        for iface in ifaces
    ]

    for ci in con_ifaces:
        for i in iface_list:
            if list(i.keys())[0] == ci.name:
                i[ci.name]['addr'] = ci.addr
                i[ci.name]['mask'] = ci.mask

    return WiapiResponse(
        success=True,
        data={ 'message': iface_list }
    )

@wiapi.post('/interfaces/monitor_mode')
@wiapi_auth_required
@wiapi_verify_interface
async def _interfaces_monitor_mode(request: Request, interface: WiapiInterface, admin_required=True) -> WiapiResponse:
    res = os.system("airmon-ng {} {}".format("start" if interface.active else "stop", interface.interface))

    if res != 0:
        raise WiapiHTTPException(
            status_code=400,
            detail="Failed to put {} into monitor mode".format(interface.interface)
        )

    return WiapiResponse()

@wiapi.post('/interfaces/deauth')
@wiapi_auth_required
@wiapi_verify_interface
async def _interfaces_deauth(request: Request, deauth: WiapiDeauth, admin_required=True) -> WiapiResponse:
    iface = list(filter(lambda i: i.name == deauth.interface, wipi.get_interfaces(17)))[0]

    if not iface.monitor_mode:
        raise WiapiHTTPException(
            status_code=400,
            detail='Bad request (interface not in monitor mode)'
        )

    bssid = re.findall(BSSID_REGEX, deauth.bssid)

    if len(bssid) != 6:
        raise WiapiHTTPException(
            status_code=400,
            detail='Bad request (invalid BSSID)'
        )

    bssid = ':'.join(bssid)

    wb = WiapiDatabase()

    try:
        p = multiprocessing.Process(target=wipi.deauth, args=(deauth.interface, bssid, deauth.packets, deauth.delay,))
        p.start()

        job = wb.add_job(deauth.interface, bssid, int(time.time()), deauth.packets, deauth.delay)
    except Exception as e:
        raise WiapiHTTPException(
            status_code=500,
            detail="Database job failed ({})".format(str(e))
        )

    job = job[0]
    id, iface, bssid, start, packets, delay, _ = job

    return WiapiResponse(
        success=True,
        data = {
            'message': {
                'job': {
                    'id': id,
                    'bssid': bssid,
                    'start': start,
                    'packets': packets,
                    'delay': delay
                }
            }
        }
    )

@wiapi.post('/scan')
@wiapi_auth_required
async def _scan(request: Request, scan_info: WiapiInterface) -> WiapiResponse:
    try:
        w = wipi.scanner(scan_info.interface)
        aps = w.scan()
        ap_list = [
            {
                'ssid': ap.ssid,
                'bssid': ap.bssid,
                'stats': ap.stats,
                'frequency': ap.frequency,
                'quality': ap.quality,
                'db': ap.db,
                'channel': ap.channel
            }

            for ap in aps
        ]

        return WiapiResponse(
            success=True,
            data={ 'message': ap_list }
        )
    except:
        raise WiapiHTTPException(
            status_code=400,
            detail="Could not initialize scanner with device specified ({})".format(scan_info.interface)
        )


