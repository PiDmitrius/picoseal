# picoseal

Secrets sealed on disk, opened only by root, used by scripts you pin in
sudoers.

## Install

    sudo ./picoseal install

Creates `/etc/picoseal` with `secrets/` inside, generates the key if there is
none, and copies the binary to `/usr/local/bin`. Running it again keeps the
existing key.

## Commands

    picoseal install          Create the directory, the key and /usr/local/bin/picoseal
    picoseal add <name>       Seal stdin under <name>
    picoseal open <name>      Print the secret
    picoseal list             List names
    picoseal remove <name>    Delete a secret
    picoseal --dir <path> ... Use another directory instead of /etc/picoseal

`add` reads one unechoed line from a terminal, under 4095 bytes, or a whole
pipe, up to 64 KiB, with one trailing newline stripped. It refuses to replace
an existing name: rotate with `remove` then `add`.

`open` writes the secret to stdout and logs the uid, the caller sudo reported,
the name and the result to syslog as `authpriv.notice`. If syslog cannot be
reached it releases nothing.

Everything but `install` reads the private key `/etc/picoseal/key`, so in
practice everything but `install` is root.

## Letting other users use a secret

Write a script that uses the secret without printing it, and read the secret
into its own variable so `set -e` catches a failure:

    #!/bin/sh
    set -eu
    GITLAB_TOKEN=$(picoseal open gitlab)
    printf 'header = "PRIVATE-TOKEN: %s"\n' "$GITLAB_TOKEN" |
        curl -sS --config - https://<gitlab>/api/v4/projects

The token goes to `curl` through its stdin config, not through `-H`: a
process's arguments are readable by every user on the machine.

Pin that script in sudoers, never `picoseal` itself — `open` with a name of the
caller's choosing is the key:

    <user> ALL=(root) NOPASSWD: /etc/picoseal/jobs.d/projects ""

The `""` forbids arguments, so the caller cannot steer the script. Keep the
script and every directory above it root-owned and not writable by the caller.
