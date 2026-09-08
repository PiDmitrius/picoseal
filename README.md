# picoseal

Secrets sealed on disk, opened only by root, used by scripts you pin in
sudoers.

## Install

    sudo ./picoseal install

Creates `/etc/picoseal` with `secrets/` and `scripts/` inside, generates the key
if there is none, and copies the binary to `/usr/local/bin`. Running it again
keeps the existing key.

## Commands

    picoseal install          Create the directory, the key and /usr/local/bin/picoseal
    picoseal add <name>       Seal stdin under <name>
    picoseal open <name>      Print the secret
    picoseal list             List names
    picoseal remove <name>    Delete a secret
    picoseal --dir <path> ... Use another directory instead of /etc/picoseal

`add` reads one unechoed line from a terminal, under 4095 bytes, or a whole
pipe, up to 65536 bytes counting the one trailing newline it strips. It refuses
to replace an existing name: rotate with `remove` then `add`.

All commands need root.

## Letting other users use a secret

Write a script in `/etc/picoseal/scripts` that uses the secret without printing
it, and read the secret into its own variable so `set -e` catches a failure:

    #!/bin/sh
    set -eu
    GITLAB_TOKEN=$(picoseal open gitlab)
    printf 'header = "PRIVATE-TOKEN: %s"\n' "$GITLAB_TOKEN" |
        curl -sS --config - https://<gitlab>/api/v4/projects

Not `-H`: that would put the token in the process arguments, which every user
on the machine can read.

Pin that script in sudoers, never `picoseal` itself — a caller who picks the
name can open every secret:

    <user> ALL=(root) NOPASSWD: /etc/picoseal/scripts/projects ""

The `""` forbids arguments, so the caller cannot steer the script. Keep the
script and every directory above it root-owned and not writable by the caller.
