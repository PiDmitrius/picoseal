# picoseal

Secrets kept in the locked memory of one service for scripts you pin in
sudoers, delivered in cryptoboxes that only the host using them can open.

A secret is a value under a name. A cryptobox is a secret locked for one key, as
one line of base64url. `picoseal serve` runs as root and holds every secret; the
other commands talk to it. It keeps a space for root and one for each user who
passes `--user`, and it learns who is asking from the kernel, not from the
caller. Each space has a session key that lives until the service stops;
`pubkey` prints its public half, `export` puts a secret in a cryptobox for it
and `import` opens that cryptobox.

Secrets stay in the service's memory, in pages locked against swap and left out
of core dumps, until the service stops or `seal`. `adde` keeps a secret there
only; `add` also keeps it on disk, in root's store with a password, as a
cryptobox for a key derived from that password. `unseal` takes out those cryptoboxes and
learns to open them; `seal` puts them away and forgets how, while cryptoboxes
sent to `pubkey` still open.

## Commands

    picoseal install          Copy the binary to /usr/local/bin
    picoseal serve            Run the service that holds the secrets
    picoseal init             Set the store password
    picoseal unseal           Ask the store password and load the secrets on disk into memory
    picoseal seal             Drop every secret from memory
    picoseal add <name>       Keep stdin as <name> in memory and in the store
    picoseal adde <name>      Keep stdin as <name> in memory only
    picoseal open <name>      Print the secret
    picoseal list             List names; "sealed" marks those on disk only, "memory" those in memory only
    picoseal remove <name>    Delete a secret from memory and disk
    picoseal pubkey           Print the session public key
    picoseal export <pubkey>  Put stdin in a cryptobox for <pubkey> and print it
    picoseal import           Open the cryptobox on stdin and print the secret
    picoseal --user ...       Use the caller's own space, in memory only, instead of root's

`add`, `adde`, `export`, `import`, `init` and `unseal` read one unechoed line
from a terminal, under 4095 bytes, or a whole pipe, up to 65536 bytes of secret
counting the one trailing newline they strip; a piped cryptobox may wrap or end
in CRLF.
`add` and `adde` refuse to replace an existing name: rotate with `remove` then
the same command again.

`add`, `adde` and `open` keep secrets; `export` and `import` make and open
cryptoboxes without keeping anything.

Every command but `export` works as root, in root's space, and refuses any other
user. `--user` works as the calling user, in that user's own space, which lives
in memory only: `adde` keeps a secret there, and `add`, `init` and `unseal`
are root's; root refuses `--user`. `export` needs neither the service nor root.
Only root reaches root's secrets, and a user reaches their own only through the
service.

## The service

Take the binary for your architecture from a release, or `go build` it, and
install it:

    chmod +x picoseal-<version>-linux-amd64
    sudo ./picoseal-<version>-linux-amd64 install

`install` copies the binary to `/usr/local/bin/picoseal`; running it again
keeps the binary's mode. Run the service under systemd:

    # /etc/systemd/system/picoseal.service
    [Service]
    ExecStart=/usr/local/bin/picoseal serve
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target

    sudo systemctl enable --now picoseal

In a container, start the service and wait for its socket before anything that
needs a secret:

    rm -f /run/picoseal.sock
    picoseal serve &
    until [ -S /run/picoseal.sock ]; do sleep 0.1; done

Every other command says so plainly when the service is not running. Stopping
or restarting it drops every secret in memory and every session key: after an
update, which is `install` and a restart, `unseal` again and deliver again what
`adde` kept.

## Memory only

Without a store, picoseal writes nothing to disk and needs no `/etc/picoseal`:
`adde` keeps secrets until the service stops, and they are delivered again
after it. The service while it answers, the clients and the program a secret is
piped to hold working copies in ordinary memory while they run.

    sudo picoseal pubkey                                  # target
    picoseal export <pubkey> < token > gitlab.box         # anywhere
    sudo picoseal import < gitlab.box | sudo picoseal adde gitlab  # target

`picoseal-export.html` does what `export` does in a browser, offline and
self-contained: paste the public key and the secret and press Export and copy,
which puts the cryptobox in the clipboard in place of the secret. Open it as a
local file or from a server you trust over https; a page served over plain http
from elsewhere can be rewritten on the way.

The session key changes every time the service starts, so take a fresh `pubkey`
over a channel that authenticates the host, such as ssh; a key swapped on the
way hands the secret to whoever swapped it. A cryptobox opens only in the space
and the run of the service it was made for.

## A store on disk

    sudo picoseal init

Only root has a store, `/etc/picoseal`. `init` sets the password, asking it
twice on a terminal and once from a pipe. From then on `add` writes every secret
to memory and to the store; it needs the store but not the password, and without
a store it fails. After the service restarts or `seal`, one `unseal` loads the
stored secrets again. Of the password the store keeps only its salt and a public
key Argon2id derives from them, so a copy of the disk opens nothing without it.
`init` and `unseal` need about 1 GiB of memory for a moment, and so does every
guess at the password. A forgotten password cannot be recovered: `seal`, remove
`unseal` and `secrets/` from the store, `init` again and deliver the secrets
again.

## Nesting

A cryptobox can go in another cryptobox: make it for the inner session first,
then for the outer one, and each host opens its own layer:

    picoseal export <inner-pubkey> < token | picoseal export <outer-pubkey> > outer.box
    sudo picoseal import < outer.box > inner.box                   # outer host
    sudo picoseal import < inner.box | sudo picoseal adde gitlab   # inner host

Each layer grows the cryptobox by about a third, and `export` takes at most
65536 bytes.

A cryptobox carries no sender identity: anyone with the public key can make
one, so accept cryptoboxes only over a channel you trust.

## Letting other users use a secret

Write a script in `/etc/picoseal/scripts` (`sudo mkdir -p` it) that uses the
secret without printing it, and read the secret into its own variable so
`set -e` catches a failure:

    #!/bin/sh
    set -eu
    GITLAB_TOKEN=$(/usr/local/bin/picoseal open gitlab)
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
reviews and installs every script that uses a secret. A forgotten `sudo` fails,
since picoseal works in another user's space only with `--user`;
`sudo chmod 700 /usr/local/bin/picoseal` also keeps the agent from reaching for
`--user`, and `install` keeps that mode. The receiving script prints nothing:

    #!/bin/sh
    # /etc/picoseal/scripts/receive <name>
    set -eu
    /usr/local/bin/picoseal import | /usr/local/bin/picoseal adde "$1"

    <agent> ALL=(root) NOPASSWD: /usr/local/bin/picoseal pubkey, /usr/local/bin/picoseal list, /etc/picoseal/scripts/receive *

With a store, `add` in place of `adde` keeps the secret on disk too. The agent
posts `sudo picoseal pubkey`, then delivers with
`printf '%s\n' '<cryptobox>' | sudo /etc/picoseal/scripts/receive gitlab` and
checks with `sudo picoseal list`. `open` and a bare `import` print the secret:
an agent that can run them sends it into its own output, so they go only into
a pipe to the program that uses the secret. Scripts do not trace (`set -x`),
run clients verbosely or put a secret in arguments.

The public key reaches the owner through the agent, which is trusted not to
swap it; a key from anywhere else is taken over ssh.
