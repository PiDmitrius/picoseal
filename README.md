# picoseal

Sealed secrets for fixed admin jobs. Anyone may wrap a secret with the public
key; only the private key opens it. An unprivileged caller never opens anything
directly — only by running a job an administrator has pinned.

The binary holds no key material.

## Boundary

picoseal makes sense only where the consuming principal cannot become root:
not in `sudo`, `docker` or `disk`, holding no NOPASSWD rule wider than the
pinned jobs, and unable to write to `/etc/sudoers.d`. A principal with any of
those reads the private key directly, and the scheme is decorative.

What it protects: a copy of the ciphertext that leaves the machine without the
key — a backup of the records, a repository, a home directory copy, an
automated agent confined to the user's uid.

What it does not protect: `wrap` is public, so whoever can write a record
controls what the job consumes, and a record carries no name — copying one over
another is not detectable. Whoever may run a job uses the secret through it
without ever reading it, so a job must be an operation whose result does not
reveal the secret. A secret handed to its intended consumer is out of reach from
that moment on.

## Install

    install -m 0755 -o root -g root picoseal /usr/local/bin/picoseal
    install -d -m 0755 -o root -g root /etc/picoseal /etc/picoseal/jobs.d
    install -d -m 0700 -o root -g root /var/lib/picoseal
    picoseal keygen

Keys live in `/etc/picoseal`, records in `/var/lib/picoseal`. Keep the two in
different backup sets: a backup holding both is plaintext.

Back up `/etc/picoseal` offline. Losing `key` turns every record into noise, and
by then the plaintext originals are gone; `key.pub` only enables `wrap`.

## Use

Wrap as any user and hand the record to the administrator. At a terminal the
secret is typed at a prompt that does not echo, so it never reaches the disk,
the shell history or a command line:

    picoseal wrap > restic.sealed
    Secret:

Terminal input is a single line under 4095 bytes, and anything typed before the
prompt appears is discarded. A record is one line of unpadded base64url and
nothing else: no header, no name, no version. It selects as a single word and
pastes anywhere.

Install the record and prove it opens:

    install -m 0644 -o root -g root restic.sealed /var/lib/picoseal/restic &&
      picoseal open /var/lib/picoseal/restic >/dev/null

A longer or multi-line secret comes from a pipe, up to 64 KiB, with one trailing
newline stripped — a value that must end in `0x0A` has to be encoded first. Then
a plaintext file exists, and it must be destroyed only once the record is
installed and proven:

    picoseal wrap < plain > restic.sealed &&
      install -m 0644 -o root -g root restic.sealed /var/lib/picoseal/restic &&
      picoseal open /var/lib/picoseal/restic >/dev/null &&
      shred -u plain

Stop at the first error. An old record at that path opens just as well, so a
skipped step would let `shred` destroy the only copy of the new secret. When the
user and the administrator are different people, the administrator confirms with
`cmp` that the installed record is byte-identical to the one handed over, before
the plaintext goes away. When replacing a record, keep the previous one aside
until the job has run with the new secret.

A job is a root script that never prints the secret:

    #!/bin/sh
    set -eu
    exec /usr/local/bin/picoseal env RESTIC_PASSWORD=/var/lib/picoseal/restic -- \
        /usr/bin/restic -r /srv/backup backup /etc

`env` passes the secret to an absolute command path and refuses a secret holding
a NUL byte; a job needing such a value reads it from `open` instead. Jobs must
ignore their arguments and set their own working directory. The script, the
records it reads, and every parent directory of both must be root-owned and not
writable by the caller.

Pin the job with no arguments, or the caller chooses them:

    <user> ALL=(root) NOPASSWD: /etc/picoseal/jobs.d/backup ""

`env_reset` must stay in effect and the consumer's own variables must not be in
`env_keep`: the tool that receives the secret still reads its own environment.

## Audit

Every open is logged to syslog as `authpriv.notice` with the uid, the caller
sudo reported, the record path and the result — next to sudo's own record of
the job. `ok` means the record was decrypted and authorized for release; it is
written before the write or the exec, so it does not confirm that the consumer
started. A forged caller is contradicted by the uid on the same line. Secrets
never reach the log. If syslog is unavailable, picoseal refuses to release the
secret.

## Not included

Key rotation, a daemon, network access, names or metadata inside a record.
