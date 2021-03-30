import urllib3
import logging
import json
import re
import os

from . import exception, _isstring

import socket
import fcntl
import struct
import time
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            ip_addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15].encode('utf-8')))[20:24])
            break
        except:
            print("Failed to get IP address on interface, retrying in 5 secs...")
            time.sleep(5)
    return ip_addr


# Suppress InsecurePlatformWarning
urllib3.disable_warnings()


_default_pool_params = dict(num_pools=3, maxsize=10, retries=3, timeout=30)
_onetime_pool_params = dict(num_pools=1, maxsize=1, retries=3, timeout=30)

_pools = {
    'default': urllib3.PoolManager(**_default_pool_params),
}

_onetime_pool_spec = (urllib3.PoolManager, _onetime_pool_params)


def set_proxy(url, basic_auth=None):
    """
    Access Bot API through a proxy.

    :param url: proxy URL
    :param basic_auth: 2-tuple ``('username', 'password')``
    """
    global _pools, _onetime_pool_spec
    if not url:
        _pools['default'] = urllib3.PoolManager(**_default_pool_params)
        _onetime_pool_spec = (urllib3.PoolManager, _onetime_pool_params)
    elif basic_auth:
        h = urllib3.make_headers(proxy_basic_auth=':'.join(basic_auth))
        _pools['default'] = urllib3.ProxyManager(url, proxy_headers=h, **_default_pool_params)
        _onetime_pool_spec = (urllib3.ProxyManager, dict(proxy_url=url, proxy_headers=h, **_onetime_pool_params))
    else:
        _pools['default'] = urllib3.ProxyManager(url, **_default_pool_params)
        _onetime_pool_spec = (urllib3.ProxyManager, dict(proxy_url=url, **_onetime_pool_params))

def set_interface(interface):
    """
    Access Bot API through a specific interface.
    """
    global _pools, _onetime_pool_spec

    ip_address = get_ip_address(interface)

    params = _default_pool_params.copy()
    params['source_address'] = (ip_address, 0)
    _pools['default'] = urllib3.PoolManager(**params)

    onetime_params = _onetime_pool_params.copy()
    onetime_params['source_address'] = (ip_address, 0)
    _onetime_pool_spec = (urllib3.PoolManager, onetime_params)

def set_source_address(ip_address):
    """
    Access Bot API using a specific source address. This is the same as the 'set_interface' method, except here the
    IP address of the desired interface is specified, rather than the interface name.
    """
    params = _default_pool_params.copy()
    params['source_address'] = (ip_address, 0)
    _pools['default'] = urllib3.PoolManager(**params)

    onetime_params = _onetime_pool_params.copy()
    onetime_params['source_address'] = (ip_address, 0)
    _onetime_pool_spec = (urllib3.PoolManager, onetime_params)


def _create_onetime_pool(*user_args):
    interface = user_args[0]
    if interface is None:
        cls, kw = _onetime_pool_spec
        return cls(**kw)
    else:
        params = _onetime_pool_params.copy()
        ip_addr = get_ip_address(interface)
        params['source_address'] = (ip_addr, 0)
        return urllib3.PoolManager(**params)


def _methodurl(req, **user_kw):
    token, method, params, files = req
    return 'https://api.telegram.org/bot%s/%s' % (token, method)

def _which_pool(req, **user_kw):
    token, method, params, files = req
    return None if files else 'default'

def _guess_filename(obj):
    name = getattr(obj, 'name', None)
    if name and _isstring(name) and name[0] != '<' and name[-1] != '>':
        return os.path.basename(name)

def _filetuple(key, f):
    if not isinstance(f, tuple):
        return (_guess_filename(f) or key, f.read())
    elif len(f) == 1:
        return (_guess_filename(f[0]) or key, f[0].read())
    elif len(f) == 2:
        return (f[0], f[1].read())
    elif len(f) == 3:
        return (f[0], f[1].read(), f[2])
    else:
        raise ValueError()

import sys
PY_3 = sys.version_info.major >= 3
def _fix_type(v):
    if isinstance(v, float if PY_3 else (long, float)):
        return str(v)
    else:
        return v

def _compose_fields(req, **user_kw):
    token, method, params, files = req

    fields = {k:_fix_type(v) for k,v in params.items()} if params is not None else {}
    if files:
        fields.update({k:_filetuple(k,v) for k,v in files.items()})

    return fields

def _default_timeout(req, **user_kw):
    name = _which_pool(req, **user_kw)
    if name is None:
        return _onetime_pool_spec[1]['timeout']
    else:
        return _pools[name].connection_pool_kw['timeout']

def _compose_kwargs(req, **user_kw):
    token, method, params, files = req
    kw = {}

    if not params and not files:
        kw['encode_multipart'] = False

    if method == 'getUpdates' and params and 'timeout' in params:
        # Ensure HTTP timeout is longer than getUpdates timeout
        kw['timeout'] = params['timeout'] + _default_timeout(req, **user_kw)
    elif files:
        # Disable timeout if uploading files. For some reason, the larger the file,
        # the longer it takes for the server to respond (after upload is finished).
        # It is unclear how long timeout should be.
        kw['timeout'] = None

    # Let user-supplied arguments override
    kw.update(user_kw)
    return kw

def _transform(req, *user_args, **user_kw):
    kwargs = _compose_kwargs(req, **user_kw)

    fields = _compose_fields(req, **user_kw)

    url = _methodurl(req, **user_kw)

    name = _which_pool(req, **user_kw)

    if name is None:
        pool = _create_onetime_pool(*user_args)
    else:
        interface = user_args[0]
        if interface is None:
            pool = _pools[name]
        else:
            params = _default_pool_params.copy()
            ip_addr = get_ip_address(interface)
            params['source_address'] = (ip_addr, 0)
            pool = urllib3.PoolManager(**params)

    return pool.request_encode_body, ('POST', url, fields), kwargs

def _parse(response):
    try:
        text = response.data.decode('utf-8')
        data = json.loads(text)
    except ValueError:  # No JSON object could be decoded
        raise exception.BadHTTPResponse(response.status, text, response)

    if data['ok']:
        return data['result']
    else:
        description, error_code = data['description'], data['error_code']

        # Look for specific error ...
        for e in exception.TelegramError.__subclasses__():
            n = len(e.DESCRIPTION_PATTERNS)
            if any(map(re.search, e.DESCRIPTION_PATTERNS, n*[description], n*[re.IGNORECASE])):
                raise e(description, error_code, data)

        # ... or raise generic error
        raise exception.TelegramError(description, error_code, data)

def request(req, *user_args, **user_kw):
    fn, args, kwargs = _transform(req, *user_args, **user_kw)
    r = fn(*args, **kwargs)  # `fn` must be thread-safe
    return _parse(r)

def _fileurl(req):
    token, path = req
    return 'https://api.telegram.org/file/bot%s/%s' % (token, path)

def download(req, *user_args, **user_kw):
    pool = _create_onetime_pool(*user_args)
    r = pool.request('GET', _fileurl(req), **user_kw)
    return r