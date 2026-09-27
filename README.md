# picoseal

Secrets kept in locked memory for scripts you pin in sudoers, delivered in
cryptoboxes that only the host using them can open.

A secret is a value under a name. A cryptobox is a secret locked for one key, as
one line of base64url. Every user and store has a session key that lives in
memory until reboot; `pubkey` prints its public half, `export` puts a secret in
a cryptobox for it and `import` opens that cryptobox.

Secrets stay in locked memory, never swapped, until reboot or `seal`. A store
with a password also keeps them on disk, as cryptoboxes for a key derived from
that password. `unseal` takes out those cryptoboxes and learns to open them;
`seal` puts them away and forgets how, while cryptoboxes sent to `pubkey` still
open.

## Commands

    picoseal install          Create the store and its key; as root also /usr/local/bin/picoseal
    picoseal unseal           Ask the store password and load the secrets on disk into memory
    picoseal seal             Drop every secret from memory
    picoseal add <name>       Keep stdin as <name>
    picoseal open <name>      Print the secret
    picoseal list             List names; "sealed" marks those on disk only
    picoseal remove <name>    Delete a secret from memory and disk
    picoseal pubkey           Print the session public key
    picoseal export <pubkey>  Put stdin in a cryptobox for <pubkey> and print it
    picoseal import           Open the cryptobox on stdin and print the secret
    picoseal --dir <path> ... Use the store at <path>

`add`, `export`, `import` and `unseal` read one unechoed line from a terminal,
under 4095 bytes, or a whole pipe, up to 65536 bytes of secret counting the one
trailing newline they strip; a piped cryptobox may wrap or end in CRLF.
`add` refuses to replace an existing name: rotate with `remove` then `add`.

`add` and `open` keep secrets; `export` and `import` make and open cryptoboxes
without keeping anything.

Root uses the store `/etc/picoseal`; everyone else keeps secrets in memory only
unless they pass `--dir`. Each store has its own session key and secrets, so
`pubkey`, `import` and `open` for one delivery take the same `--dir`. Only root
reads root's secrets. systemd-logind drops the memory of a user other than root
when their last session ends, unless `loginctl enable-linger` keeps it.

## Memory only

Without a store password, picoseal writes nothing to disk: secrets live until
reboot and are delivered again after it. A running picoseal and the program a
secret is piped to hold working copies in ordinary memory while they run.

    sudo picoseal pubkey                                  # target
    picoseal export <pubkey> < token > gitlab.box         # anywhere, no root
    sudo picoseal import < gitlab.box | sudo picoseal add gitlab   # target

`picoseal-export.html` does what `export` does in a browser, offline and
self-contained: paste the public key and the secret, then copy the cryptobox.
Open it as a local file or from a server you trust over https; a page served
over plain http from elsewhere can be rewritten on the way.

The session key changes on every reboot, so take a fresh `pubkey` over a channel
that authenticates the host, such as ssh; a key swapped on the way hands the
secret to whoever swapped it. A cryptobox opens only in the session it was
made for.

## A store on disk

    sudo ./picoseal install
    sudo picoseal unseal

`install` creates `/etc/picoseal` with `secrets/` and `scripts/` and the store
key, and copies the binary to `/usr/local/bin`; running it again keeps the key.
The first `unseal` asks the password twice, on a terminal, and writes to
`secrets/` the secrets already in memory; from then on `add` also writes every
secret there, even before the next `unseal`.
After a reboot or `seal`, one `unseal` loads them all again. The password and
the store key are both needed: a copy of the disk without the password opens
nothing, and neither does the password alone. `unseal` needs about 1 GiB of
memory.

## Nesting

A cryptobox can go in another cryptobox: make it for the inner session first,
then for the outer one, and each host opens its own layer:

    picoseal export <inner-pubkey> < token | picoseal export <outer-pubkey> > outer.box
    sudo picoseal import < outer.box > inner.box                   # outer host
    sudo picoseal import < inner.box | sudo picoseal add gitlab    # inner host

Each layer grows the cryptobox by about a third, and `export` takes at most
65536 bytes.

A cryptobox carries no sender identity: anyone with the public key can make
one, so accept cryptoboxes only over a channel you trust.

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

Pin that script in sudoers, never `picoseal` with free arguments — a caller who
picks the name can open every secret:

    <user> ALL=(root) NOPASSWD: /etc/picoseal/scripts/projects ""

The `""` forbids arguments, so the caller cannot steer the script. Keep the
script and every directory above it root-owned and not writable by the caller.

## Agents

An agent that operates a host gets a secret the same way and never needs to
see it: the owner turns the secret into a cryptobox in `picoseal-export.html`
and posts it in the chat, and the agent hands it to a script that keeps it.
Only cryptoboxes then reach the chat, the model and the tool output.

That holds by setup, not by the agent's care, when the agent's user has no
root, no `sudo` beyond the lines below and no `docker` group, and the owner
reviews and installs every script that uses a secret. The receiving script
prints nothing:

    #!/bin/sh
    # /etc/picoseal/scripts/receive <name>
    set -eu
    picoseal import | picoseal add "$1"

    <agent> ALL=(root) NOPASSWD: /usr/local/bin/picoseal pubkey, /usr/local/bin/picoseal list, /etc/picoseal/scripts/receive *

The agent posts `sudo picoseal pubkey`, then delivers with
`printf '%s\n' '<cryptobox>' | sudo /etc/picoseal/scripts/receive gitlab` and
checks with `sudo picoseal list`. `open` and a bare `import` print the secret:
an agent that can run them sends it into its own output, so they go only into
a pipe to the program that uses the secret. Scripts do not trace (`set -x`),
run clients verbosely or put a secret in arguments.

The public key reaches the owner through the agent, which is trusted not to
swap it; a key from anywhere else is taken over ssh.
