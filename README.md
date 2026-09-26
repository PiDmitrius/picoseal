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
    picoseal export <pubkey>  Seal stdin for the host with <pubkey> and print the record
    picoseal import           Print the secret in a record on stdin
    picoseal pubkey           Print the public key
    picoseal open <name>      Print the secret
    picoseal list             List names
    picoseal remove <name>    Delete a secret
    picoseal --dir <path> ... Use another directory instead of /etc/picoseal

`add` reads one unechoed line from a terminal, under 4095 bytes, or a whole
pipe, up to 65536 bytes counting the one trailing newline it strips. It refuses
to replace an existing name: rotate with `remove` then `add`. `export` reads
stdin the same way.

`add` and `open` keep secrets in the store; `export` and `import` seal and open
a stream for one host without touching any store.

All commands but `export` need root.

## Sealing for another host

The public key is not secret; hand it to whoever should deliver a secret:

    sudo picoseal pubkey

Anyone with it seals a record on any machine, without root and without the
private key, and the target opens it into a file or its own store:

    picoseal export <pubkey> < token > gitlab.rec
    sudo picoseal import < gitlab.rec | sudo picoseal add gitlab

A record is itself a stream, so records nest: seal for the inner host first,
then for the outer one, and each host opens its own layer:

    picoseal export <inner-pubkey> < token | picoseal export <outer-pubkey> > outer.rec
    sudo picoseal import < outer.rec > inner.rec         # outer host
    sudo picoseal import < inner.rec | sudo picoseal add gitlab   # inner host

Each layer grows the record by about a third, and `export` takes at most
65536 bytes.

A record carries no sender identity: anyone with the public key can make one,
so accept records only over a channel you trust.

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
