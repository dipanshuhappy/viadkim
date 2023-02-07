# viadkim

<br>

🚧

***experimental, in development***

🏗

<br>

The **viadkim** library contains an implementation of DomainKeys Identified Mail
(DKIM). DKIM is specified in [RFC 6376].

This library provides both high-level APIs for signing and verifying email
messages, as well as the low-level APIs used to implement this functionality.
It is an asynchronous library based on the Tokio async runtime.

TODO API is experimental, in initial development

In terms of API, the main goals of viadkim are: efficiency, resilience with
regard to inputs, and RFC conformance.

Efficiency means, for example, doing DNS requests concurrently. Or, for example,
message data can be processed in chunks, and if the necessary amount of chunks
has been received can shortcut to finalisation, without the whole message being
in memory at once. Or, for example, body canonicalisation is done only once even
if multiple signatures request the same canonicalisation.

As for resilience when handling inputs, this means, for example, that viadkim is
lenient with regard to encoding errors in inputs: stray Latin 1 bytes in headers
pose no problem for this library, they are handled transparently as byte
strings. Or, for example, internationalised email is supported and such inputs
are again handled in the correct manner.

Finally, the meaning of RFC conformance requires no explanation. It does mean,
for example, that the supported signature algorithms, for both signing and
verifying, include only `rsa-sha256` and `ed25519-sha256`. The historic
signature algorithm `rsa-sha1` is not supported, and similarly RSA key sizes
below 1024 bits are not supported (see [RFC 8301]).

[RFC 6376]: https://www.rfc-editor.org/rfc/rfc6376
[RFC 8301]: https://www.rfc-editor.org/rfc/rfc8301

## Usage

TODO

DNS resolution is abstracted in trait `LookupTxt`.

A lookup implementation of the `LookupTxt` trait can be made available for the
Trust-DNS async resolver by enabling feature `trust-dns-resolver`.

## Example

TODO dkimverify

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
