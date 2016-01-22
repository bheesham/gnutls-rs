gnutls-rs
===========

A work in progress. Do not use this.

## Building

You will need to have the GnuTLS development libraries, and the rust-bindgen
executable.

Generate new bindings by running the following, then editing the output to get
rid of the invariants:

```
bindgen -lgnutls -builtins -o gnutls-sys/src/gen.rs -i gnutls-sys/src/inc.h
```

<hr>

Like GnuTLS, this code is licensed under the LGPLv2. A copy of the license can
be found in `COPYING.LESSER`.

Copyright (C) 2015 Bheesham Persaud.

