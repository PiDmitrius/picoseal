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

Never pin `picoseal` itself in sudoers. A caller who can reach `open` or `env`
with a record path of their choosing holds the key, whatever the argument
pattern looks like. Pin jobs, never the tool.

What it protects: a copy of the ciphertext that leaves the machine without the
key — a backup of the records, a repository, a home directory copy, an
automated agent confined to the user's uid.

What it does not protect: `wrap` is public, so whoever can write a record
controls what the job consumes, and a record carries no name — copying one over
another is not detectable. Whoever may run a job uses the secret through it
without ever reading it, so a job must be an operation whose result does not
reveal the secret. A secret handed to its intended consumer is out of reach from
that moment on.

Moving a secret here does not act backwards: backups and snapshots taken before
the move, repository history, and blocks freed by `shred` on a copy-on-write
filesystem still hold the plaintext. They have to expire or be destroyed, or the
protection above is only about new copies.

## Install

    install -m 0755 -o root -g root picoseal /usr/local/bin/picoseal
    install -d -m 0755 -o root -g root /etc/picoseal /etc/picoseal/jobs.d
    install -d -m 0700 -o root -g root /var/lib/picoseal
    picoseal keygen

Keys live in `/etc/picoseal`, records in `/var/lib/picoseal`, job scripts in
`/etc/picoseal/jobs.d`. Keep keys and records in different backup sets: a backup
holding both is plaintext.

Back up `/etc/picoseal` offline. Losing `key` turns every record into noise, and
by then the plaintext originals are gone; `key.pub` only enables `wrap`.

## Use

Wrap as any user and hand the record to the administrator. At a terminal the
secret is typed at a prompt that does not echo, so picoseal never writes it to a
file and it stays out of the shell history and of any command line:

    picoseal wrap > restic.sealed
    Secret:

Terminal input is a single line under 4095 bytes, and anything typed before the
prompt appears is discarded. A record is one line of unpadded base64url and
nothing else: no header, no name, no version. Its alphabet is `[A-Za-z0-9_-]`,
so it survives copy and paste as one word.

Install a record beside its live path, prove that one opens, and only then
publish it by rename — a job running at that moment reads either the whole old
record or the whole new one:

    install -m 0600 -o root -g root restic.sealed /var/lib/picoseal/.restic.new &&
      picoseal open /var/lib/picoseal/.restic.new >/dev/null &&
      mv /var/lib/picoseal/.restic.new /var/lib/picoseal/restic

A longer or multi-line secret comes from a pipe, up to 64 KiB, with one trailing
newline stripped — a value that must end in `0x0A` has to be encoded first. Then
a plaintext file exists, and it goes away only after the same proof:

    picoseal wrap < plain > restic.sealed &&
      install -m 0600 -o root -g root restic.sealed /var/lib/picoseal/.restic.new &&
      picoseal open /var/lib/picoseal/.restic.new >/dev/null &&
      mv /var/lib/picoseal/.restic.new /var/lib/picoseal/restic &&
      shred -u plain

Stop at the first error, and keep the previous record aside until the job has
run with the new secret. The proof deliberately runs on the file just staged,
never on the live path: an old record there opens just as well, so proving the
live path would say nothing about the new secret. Because a sealed box is
authenticated, that one `open` covers both a record damaged in transfer and a
record sealed to a key this host does not hold.

A job is a root script in `/etc/picoseal/jobs.d` that never prints the secret:

    #!/bin/sh
    set -eu
    exec /usr/local/bin/picoseal env RESTIC_PASSWORD=/var/lib/picoseal/restic -- \
        /usr/bin/restic -r /srv/backup backup /etc

Records and the command are named by absolute path; picoseal refuses anything
else, because sudo leaves the caller's working directory in place. `env` refuses
a secret holding a NUL byte; a job needing such a value reads it from `open`
instead. Jobs must ignore their arguments and set their own working directory.
The script, the records it reads, and every parent directory of both must be
root-owned and not writable by the caller.

Pin the job with no arguments, or the caller chooses them:

    <user> ALL=(root) NOPASSWD: /etc/picoseal/jobs.d/backup ""

`env_reset` must stay in effect and the consumer's own variables must not be in
`env_keep`: the tool that receives the secret still reads its own environment.

## Audit

Every open is logged to syslog as `authpriv.notice` with the uid, the caller
sudo reported, the record path and the result — next to sudo's own record of
the job. `ok` means the record was decrypted and authorized for release; it is
written before the write or the exec, so it does not confirm that the consumer
started. Secrets never reach the log.

The text of an entry proves nothing by itself: any local process can send a
line with the same tag and any uid in it. Trust the receiver's own metadata —
`_UID` and `_PID` in the journal — and sudo's record of the job.

Unprivileged attempts are logged too, so a local user can generate this traffic;
how much of it survives is journald's rate limit, not picoseal's concern. If
syslog cannot be reached, picoseal refuses to release the secret — that covers
delivery to the log socket, not whether the log was later persisted.

## Not included

Key rotation, a daemon, network access, names or metadata inside a record.
