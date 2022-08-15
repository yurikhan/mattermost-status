# Status client for Mattermost

Mattermost has a manual knob
for pausing notifications until a given time point,
but (as of now) no way to set a schedule
so that notifications are paused at the end of every work day.
There is [an issue][MM-35343] and who knows when it is implemented.

[MM-35343]: https://mattermost.atlassian.net/browse/MM-35343

However, Mattermost has a [documented API][api].
And that API lets us specify a status and an expiration time.
So we can set statuses programmatically.

[api]: https://api.mattermost.com/#operation/UpdateUserStatus

And then we can put a command to set the status into a crontab.
(If you are on Windows, use Scheduled Tasks instead.)
Boom! DND schedule on the cheap.


## Dependencies

Python 3.8+ and a few thirdparty libraries:

* [appdirs](https://pypi.org/project/appdirs/)
* [iso8601](https://pypi.org/project/iso8601/)
* [requests](https://pypi.org/project/requests/)

On Ubuntu, you can install these with:

```bash
$ sudo apt install python3-appdirs python3-iso8601 python3-requests
```

Otherwise, `pip3` is your friend.


## Basic usage examples

```bash
$ ./mm-status -s https://mm.example.com/ -u myname login
```

This will ask you for your password,
log in and store a login token in your home directory.
After this, the following commands will work.

```bash
$ ./mm-status dnd --for=PT15H
```

Set the Do Not Disturb status for 15 hours.
(The `--for` option uses ISO 8601 syntax for intervals.)

```bash
$ ./mm-status dnd --until=2022-08-17T10:00
```

Same but until a specific time in your local time zone.
(You can use any valid ISO 8601 date+time here.)

```bash
$ ./mm-status online
```

Go back online.

```bash
$ ./mm-status custom --for PT15H --emoji zzz 'Not working'
```

Set a custom status.
`--until` works, too.

```bash
$ ./mm-status --help
$ ./mm-status <subcommand> --help
```

Read this!