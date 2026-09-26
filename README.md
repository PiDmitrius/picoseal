# picoseal

Secrets kept in locked memory for scripts you pin in sudoers, delivered sealed
for the host that uses them.

Every user has a session key that lives in memory until reboot. Secrets added
or delivered stay in memory, never swapped, until reboot or `seal`. A store
with an unseal password also keeps them on disk, sealed for a key derived from
that password, and loads them back on `unseal`.

## Commands

    picoseal install          Create the store, its key and /usr/local/bin/picoseal
    picoseal unseal           Ask the store password and load the store into memory
    picoseal seal             Drop every secret from memory
    picoseal add <name>       Keep stdin as <name>
    picoseal open <name>      Print the secret
    picoseal list             List names; "sealed" marks those on disk only
    picoseal remove <name>    Delete a secret from memory and disk
    picoseal pubkey           Print the session public key
    picoseal export <pubkey>  Seal stdin for the session with <pubkey> and print the record
    picoseal import           Print the stream in a record on stdin
    picoseal --dir <path> ... Use the store at <path>

`add` and `export` read one unechoed line from a terminal, under 4095 bytes, or
a whole pipe, up to 65536 bytes counting the one trailing newline they strip.
`add` refuses to replace an existing name: rotate with `remove` then `add`.

`add` and `open` keep secrets; `export` and `import` seal and open a stream for
one session without keeping anything.

Root uses the store `/etc/picoseal`; everyone else keeps secrets in memory only
unless they pass `--dir`. Only root reads root's secrets. systemd-logind drops
the memory of a user other than root when their last session ends, unless
`loginctl enable-linger` keeps it.

## Memory only

Without a store password, nothing reaches the disk: secrets live until reboot
and are delivered again after it.

    sudo picoseal pubkey                                  # target
    picoseal export <pubkey> < token > gitlab.rec         # anywhere, no root
    sudo picoseal import < gitlab.rec | sudo picoseal add gitlab   # target

The session key changes on every reboot, so take a fresh `pubkey` over a channel
that authenticates the host, such as ssh; a key swapped on the way hands the
secret to whoever swapped it. A record opens only in the session it was sealed
for.

## A store on disk

    sudo ./picoseal install
    sudo picoseal unseal

`install` creates `/etc/picoseal` with `secrets/` and `scripts/` and the store
key, and copies the binary to `/usr/local/bin`; running it again keeps the key.
The first `unseal` asks the password twice, on a terminal, and from then on
`add` also writes every secret to `secrets/`, even before the next `unseal`.
After a reboot or `seal`, one `unseal` loads them all again. The password and
the store key are both needed: a copy of the disk without the password opens
nothing, and neither does the password alone. `unseal` needs about 1 GiB of
memory.

## Nesting

A record is itself a stream, so records nest: seal for the inner session first,
then for the outer one, and each host opens its own layer:

    picoseal export <inner-pubkey> < token | picoseal export <outer-pubkey> > outer.rec
    sudo picoseal import < outer.rec > inner.rec                   # outer host
    sudo picoseal import < inner.rec | sudo picoseal add gitlab    # inner host

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
