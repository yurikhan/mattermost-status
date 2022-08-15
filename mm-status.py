#!/usr/bin/env python3

import argparse
from argparse import ArgumentParser
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import partial
from getpass import getpass
import json
from pathlib import Path
import re
import sys
from textwrap import dedent
from typing import Any, Callable, Dict, List, TypedDict, Optional, Union, cast
from urllib.parse import urljoin, urlsplit

# apt install python3-appdirs python3-iso8601 python3-requests
# or pip install appdirs iso8601 requests
import appdirs   # license: MIT
import iso8601   # license: MIT
import requests  # license: Apache 2.0


HostName = str
JsonValue = Union[None, bool, int, float, str, List[Any], Dict[str, Any]]
LoginId = str
SessionToken = str
Url = str
UserId = str


class Status(str, Enum):
    online = 'online'
    away = 'away'
    offline = 'offline'
    dnd = 'dnd'

    def __str__(self) -> str:
        return self.name


class Cache(TypedDict):
    id: UserId
    token: SessionToken


class CacheFile:
    def __init__(self, server: HostName, login_id: LoginId) -> None:
        self._path = Path(appdirs.user_cache_dir('mm-status')) / server / login_id

    def read(self) -> Optional[Cache]:
        return json.loads(self._path.read_text()) if self._path.is_file() else None

    def write(self, cache: Optional[Cache]) -> None:
        if cache is None:
            self.wipe()
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(mode=0o600)
        self._path.chmod(mode=0o600)
        self._path.write_text(json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True))

    def wipe(self) -> None:
        self._path.unlink(missing_ok=True)


class Mattermost:
    def __init__(self, base: Url, verbose: bool) -> None:
        self._base = urljoin(base, '/api/v4/')
        self._verbose = verbose
        self._session_token: Optional[SessionToken] = None
        self._user_id: Optional[UserId] = None

    def _request(self, method: str, url: Url, **kwargs: Any) -> requests.Response:
        headers = kwargs.pop('headers', {})
        response = requests.request(
            method, urljoin(self._base, url),
            headers={**headers,
                     **({'Authorization': f'Bearer {self._session_token}'}
                        if self._session_token is not None else {}),
                     'User-Agent': 'mm-status/0.0.1 (@y.khan)'},
            **kwargs)
        if self._verbose:
            print(f'> {response.request.method} {response.request.url}', file=sys.stderr)
            print('\n'.join(f'> {k}: {v}' for k, v in response.request.headers.items()),
                  file=sys.stderr)
            if response.request.body is None:
                pass
            elif isinstance(response.request.body, str):
                print('>', file=sys.stderr)
                print('\n'.join(f'> {line}'
                                for line in response.request.body.splitlines()),
                      file=sys.stderr)
            elif response.request.headers['Content-Type'] == 'application/json':
                print('>', file=sys.stderr)
                print('\n'.join(f'> {line}'
                                for line in response.request.body.decode('utf-8').splitlines()),
                      file=sys.stderr)
            else:
                print('>', file=sys.stderr)
                print('> <binary data>', file=sys.stderr)
            print(file=sys.stderr)
            print(f'< {response.status_code} {response.reason}', file=sys.stderr)
            print('\n'.join(f'< {k}: {v}' for k, v in response.headers.items()), file=sys.stderr)
            print('<', file=sys.stderr)
            if response.encoding is not None:
                print('\n'.join(f'< {line}' for line in response.text.splitlines()),
                      file=sys.stderr)
            else:
                print('< <binary data>', file=sys.stderr)
            print(file=sys.stderr)
        if not response.ok:
            print(response.json().get('message', ''), file=sys.stderr)
        response.raise_for_status()
        return response

    def _get(self, url: Url, **kwargs: Any) -> requests.Response:
        return self._request('get', url, **kwargs)

    def _delete(self, url: Url, **kwargs: Any) -> requests.Response:
        return self._request('delete', url, **kwargs)

    def _post(self, url: Url, **kwargs: Any) -> requests.Response:
        return self._request('post', url, **kwargs)

    def _put(self, url: Url, **kwargs: Any) -> requests.Response:
        return self._request('put', url, **kwargs)

    def login(self, login_id: LoginId, *, password: Optional[str] = None,
              cache: Optional[Cache] = None) -> Optional[Cache]:
        if password is not None:
            response = self._post('users/login', json={'login_id': login_id, 'password': password})
            self._session_token = response.headers['token']
            self._user_id = response.json()['id']
        elif cache is not None:
            self._session_token = cache['token']
            self._user_id = cache['id']
        return ({'id': self._user_id, 'token': self._session_token}
                if self._user_id is not None and self._session_token is not None
                else None)

    def set_status(self, status: Status, dnd_end_time: Optional[datetime] = None) -> None:
        self._put(f'users/{self._user_id}/status',
                  json={'user_id': self._user_id, 'status': str(status),
                        **({'dnd_end_time': int(dnd_end_time.timestamp())}
                           if dnd_end_time is not None else {})})

    def set_custom_status(self, emoji: str, text: str,
                          expires_at: Optional[datetime] = None) -> None:
        expires_utc = expires_at.astimezone(timezone.utc) if expires_at is not None else None
        self._put(f'users/{self._user_id}/status/custom',
                  json={'emoji': emoji, 'text': text,
                        **({'expires_at': f'{expires_utc:%Y-%m-%dT%H:%M:%SZ}'}
                           if expires_at is not None else {})})

    def unset_custom_status(self) -> None:
        self._delete(f'users/{self._user_id}/status/custom')


def validate_url(s: str) -> str:
    scheme, netloc, *_ = urlsplit(s)
    if not (scheme and netloc):
        raise ValueError('Invalid URL')
    return s


TIMEDELTA_RE = re.compile(
    r'[Pp](?:(?P<days>[0-9]+)[Dd])?'
    r'(?:[Tt](?:'
    r'(?:(?P<hours>[0-9]+)[Hh])?'
    r'(?:(?P<minutes>[0-9])+[Mm])?'
    r'(?:(?P<seconds>[0-9]+(?:\.[0-9]+)?)[Ss])?'
    r'))?|'
    r'P(?:(?P<weeks>[0-9]+)[Ww])')


def parse_timedelta(s: str) -> timedelta:
    m = TIMEDELTA_RE.fullmatch(s)
    if not m or not m.groupdict():
        raise ValueError('Invalid time interval')
    return timedelta(**{k: float(v)
                        for k, v in m.groupdict().items()
                        if v is not None})


def parse_relative_time(s: str) -> datetime:
    delta = parse_timedelta(s)
    return datetime.now() + delta


def argument(*args: Any, **kwargs: Any) -> Callable[[Callable], Callable]:
    def decorator(f: Callable) -> Callable:
        setattr(f, '_add_arguments',
                [(args, kwargs),
                 *getattr(f, '_add_arguments', [])])
        return f

    return decorator


def duration_arguments(f: Callable) -> Callable:
    f = argument('--until', metavar='yyyy-mm-ddThh:mm:ss[Z|±hh[:]mm]',
                 type=partial(iso8601.parse_date, default_timezone=None),
                 help=('end dnd at the specified time. '
                       'Z means UTC time, +hh:mm is east of Greenwich, '
                       '-hh:mm west of Greenwich, no time zone means local, '
                       'seconds can be fractional'))(f)
    f = argument('--for', dest='until', metavar='P[nD][T[nH][nM][nS]]|PnW',
                 type=parse_relative_time,
                 help=('end dnd after the given time interval. '
                       'nD specifies days, '
                       'nH, nM, and nS mean hours, minutes, and seconds respectively. '
                       'Alternatively, PnW specifies weeks. '
                       'At least one unit must be specified. '
                       'See ISO 8601.'))(f)
    return f


def default_server() -> Url:
    servers = list(Path(appdirs.user_cache_dir('mm-status')).iterdir())
    if len(servers) == 1:
        return servers[0].name
    raise ValueError('Caches for more than one server found, please specify')


def default_user(server: Url) -> LoginId:
    logins = list((Path(appdirs.user_cache_dir('mm-status')) / server).iterdir())
    if len(logins) == 1:
        return logins[0].name
    raise ValueError('Caches for more than one user found, please specify')


@argument('-s', '--server', metavar='URL', type=validate_url,
          help='your Mattermost instance URL, e.g.: https://mattermost.mycompany.example/')
@argument('-u', '--user', metavar='USERID', help='user name or email address')
@argument('-v', '--verbose', action='store_true', help='display API requests and responses')
class Cli:
    """
    Control Mattermost status.

    To set a DND schedule, put this in your user crontab:

        0 20 * * 1-4  <path>/%(prog)s dnd --for PT15H
        0 20 * * 5    <path>/%(prog)s dnd --for P2DT15H

    (The first line sets DND at 20:00 on Mon–Thu, for 15 hours, i.e. until 11:00
    next day. The second line sets DND at 20:00 on Fri, for 2 days 15 hours,
    i.e. until 11:00 Mon. See crontab(1) and crontab(5) for details. Also, if
    you use a non-standard $XDG_DATA_HOME, set that in your crontab, too.)

    NOTE that you need to log in once with ‘%(prog)s --server … --user … login’.
    This will store a token in your cache directory, which will allow the script
    to work without asking you for a password every time.
    """

    def __init__(self, args: argparse.Namespace) -> None:
        server = urlsplit(args.server).hostname or default_server()
        self._user = args.user or default_user(server)
        self._cache_file = CacheFile(server, self._user)
        self._mattermost = Mattermost(args.server or f'https://{server}/', args.verbose)
        self._args = args

    def login(self) -> None:
        """log in and store token"""
        self._cache_file.write(self._mattermost.login(self._user, password=getpass()))

    def logout(self) -> None:
        """wipe token"""
        self._cache_file.wipe()

    def online(self) -> None:
        """set status to online"""
        self._restore_cache()
        self._mattermost.set_status(status=Status.online)

    def away(self) -> None:
        """set status to away"""
        self._restore_cache()
        self._mattermost.set_status(status=Status.away)

    def offline(self) -> None:
        """set status to offline"""
        self._restore_cache()
        self._mattermost.set_status(status=Status.offline)

    @duration_arguments
    def dnd(self) -> None:
        """set status to dnd"""
        self._restore_cache()
        self._mattermost.set_status(status=Status.dnd, dnd_end_time=self._args.until)

    @argument('-d', '--unset', action='store_true', help='unset custom status')
    @argument('--emoji', metavar='STRING',
              help='emoji for the custom status (no :…: delimiters)')
    @duration_arguments
    @argument('text', nargs='?', help='custom status text')
    def custom(self) -> None:
        "set or unset custom status"
        self._restore_cache()
        if self._args.unset:
            self._mattermost.unset_custom_status()
        else:
            if not (self._args.emoji and self._args.text):
                raise ValueError('--emoji and text are required')
            self._mattermost.set_custom_status(emoji=self._args.emoji, text=self._args.text,
                                               expires_at=self._args.until)

    def _restore_cache(self) -> None:
        self._mattermost.login(self._args.user, cache=self._cache_file.read())


def parse_args() -> argparse.Namespace:
    parser = ArgumentParser(description=dedent(cast(str, Cli.__doc__)),
                            formatter_class=argparse.RawDescriptionHelpFormatter)
    for args, kwargs in getattr(Cli, '_add_arguments', []):
        parser.add_argument(*args, **kwargs)
    subcommands = parser.add_subparsers(title='subcommands', metavar='SUBCOMMAND')

    for command, handler in Cli.__dict__.items():
        if command.startswith('_'):
            continue
        command_parser = subcommands.add_parser(command, description=handler.__doc__,
                                                help=handler.__doc__)
        command_parser.set_defaults(handler=handler)
        for args, kwargs in getattr(handler, '_add_arguments', []):
            command_parser.add_argument(*args, **kwargs)

    return parser.parse_args()


def main():
    args = parse_args()
    args.handler(Cli(args))


if __name__ == '__main__':
    main()
