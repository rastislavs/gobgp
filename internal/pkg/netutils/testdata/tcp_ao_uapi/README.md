# TCP-AO Linux UAPI golden records

The `.hex` files are complete Linux socket-option records used by the portable
Go tests. They are generated through named fields in the installed Linux UAPI,
so the tests do not duplicate byte offsets from `struct tcp_ao_add`,
`struct tcp_ao_del`, or `struct tcp_ao_info_opt`.

Regenerate them on a little-endian Linux `amd64` or `arm64` host whose
`<linux/tcp.h>` provides TCP-AO:

```sh
cc -std=c11 -Wall -Wextra -Werror generate.c -o /tmp/gobgp-tcp-ao-golden
/tmp/gobgp-tcp-ao-golden .
```

Review the resulting fixture diff and run the TCP-AO live tests before
accepting an ABI change. Ordinary Go tests only read the committed `.hex`
files and do not require a C compiler or Linux headers.
