# viadkim

<br>

🚧

***experimental, in development***

🏗

<br>

TODO

The **viadkim** library contains a complete implementation of DomainKeys
Identified Mail (DKIM). DKIM is specified in [RFC 6376].

This library provides both high-level APIs for signing and verifying email
messages, as well as the low-level APIs used to implement this functionality. It
is an asynchronous library based on the Tokio async runtime.

This library is developed independently from scratch, by following the RFC
specification and related documents. The design objectives sketched below are
used to guide development.

## Design objectives

TODO

The goal of viadkim is to provide a free DKIM library suitable for long-lived
mail server processes, with strong RFC conformance guarantees.

Of particular importance is that the library should be **efficient**. Some items
of note in this rubric are: doing DNS requests for public key records
concurrently; bypass or shortcut message body processing where this is possible,
and without the whole message being in memory at once; or sharing message body
canonicalisation results among signature evaluation tasks.

Of equal importance is a certain **resilience** and broad **compatibility in
handling inputs**. Notably, internationalised email is fully supported in
viadkim. But also malformed inputs that do occur in practice, such as stray
Latin 1 bytes in headers are handled transparently. Generally, all inputs are
handled gracefully, and similarly all outputs should be well-formed.

Care is taken to **conform** strictly to **RFC 6376**, including RFC updates and
known errata. Internationalised email was already mentioned. Also, for example,
for both signing and verifying only the signature algorithms `rsa-sha256` and
`ed25519-sha256` are supported, the historic signature algorithm `rsa-sha1` was
retired and is not supported (unless explicitly enabled; see [RFC 8301]).

[RFC 6376]: https://www.rfc-editor.org/rfc/rfc6376
[RFC 8301]: https://www.rfc-editor.org/rfc/rfc8301

## Usage

TODO

Two structs provide the main entry points to DKIM processing with viadkim:
`Signer` for signing a message, and `Verifier` for verifying a message’s
signatures.

DNS resolution is abstracted in trait `LookupTxt`.

A lookup implementation of the `LookupTxt` trait can be made available for the
Trust-DNS async resolver by enabling feature `trust-dns-resolver`.

## Examples

Two simple command-line utilities are included as examples, one for signing a
message, and one for verifying a message’s signatures.

The program **`dkimsign`** produces a DKIM signature for the message provided on
standard input. It takes three arguments: a path to a key file containing a
signing key in PKCS#8 PEM format, a domain (the *d=* tag), and a selector (the
*s=* tag). It then prints a DKIM-Signature header that can be prepended to the
message.

Example invocation:

```
cargo run --example dkimsign -- \
  /path/to/key.pem example.com selector < /path/to/msg-to-sign
```

The program **`dkimverify`** verifies the DKIM signatures of a message provided
on standard input. It prints each verification result with signature as Rust
data structures.

Example invocation:

```
cargo run --features trust-dns-resolver \
  --example dkimverify < /path/to/msg-to-verify
```

In both examples, export the environment variable `RUST_LOG=viadkim=trace` to
enable the library’s trace logging.

Edit these examples to experiment with various configuration options.

## Acknowledgments

While this is an independent implementation of DKIM that was created from
scratch, the author wants to give credit to the [OpenDKIM] project. As a
long-time user of OpenDKIM, some design choices made here were inspired by it.
For example, the ‘staged’ design, which does not require that the whole message
reside in memory at once, is inspired from OpenDKIM.

[OpenDKIM]: http://opendkim.org

## Licence

Copyright © 2022–2023 David Bürgin

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see https://www.gnu.org/licenses/.
