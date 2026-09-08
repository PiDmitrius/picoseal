# picoseal

Sealed secrets for fixed admin jobs. Only root adds and opens a secret; an
unprivileged caller reaches one only by running a job an administrator has
pinned in sudoers.

The binary holds no key material — the private key and the records are
protected by file permissions.

## Boundary

picoseal makes sense only where the consuming principal cannot become root:
not in `sudo`, `docker` or `disk`, holding no NOPASSWD rule wider than the
pinned jobs, and unable to write to `/etc/sudoers.d`. A principal with any of
those reads the private key directly, and the scheme is decorative.

Never pin `picoseal` itself. A caller who can reach `open` with a name of their
choosing holds the key, whatever the argument pattern looks like. Pin jobs.

What it protects: a copy of the records that leaves the machine without the
key, and any process confined to the user's uid.

What it does not protect: whoever may run a job uses the secret through it
without ever reading it, so a job must be an operation whose result does not
reveal the secret. A secret handed to its consumer is out of reach from that
moment on. Losing `key` makes every record unreadable.

## Install

    sudo ./picoseal install

Creates `/etc/picoseal` with `secrets/` inside, generates the key if there is
none, and copies the binary to `/usr/local/bin`. Running it again keeps the
existing key.

## Use

    sudo picoseal add restic          # prompts, does not echo
    sudo picoseal list
    sudo picoseal open restic         # prints the secret
    sudo picoseal remove restic

`add` refuses to replace an existing name; rotate with `remove` then `add`. A
secret longer than one terminal line comes from a pipe, up to 64 KiB, with one
trailing newline stripped — a value that must end in `0x0A` has to be encoded
first.

A job is a root script in `/etc/picoseal/jobs.d` that never prints the secret.
Read it into a variable of its own, so `set -e` catches a failure:

    #!/bin/sh
    set -eu
    RESTIC_PASSWORD=$(picoseal open restic)
    export RESTIC_PASSWORD
    exec /usr/bin/restic -r /srv/backup backup /etc

Jobs must ignore their arguments and call tools by absolute path. The script and
every parent directory must be root-owned and not writable by the caller. Pin
the job with no arguments, or the caller chooses them:

    <user> ALL=(root) NOPASSWD: /etc/picoseal/jobs.d/backup ""

## Audit

Every open goes to syslog as `authpriv.notice` with the uid, the caller sudo
reported, the name and the result — next to sudo's own record of the job. The
text of an entry proves nothing by itself: any local process can send a line
with the same tag. Trust the receiver's metadata — `_UID` and `_PID` in the
journal — and sudo's record. Secrets never reach the log, and if syslog cannot
be reached picoseal refuses to release the secret.

## Not included

Key rotation, a daemon, network access, names or metadata inside a record.
