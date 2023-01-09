# viadkim

<br>

***experimental, in development***

<br>

The **viadkim** library contains an implementation of DomainKeys Identified Mail
(DKIM). DKIM is specified in [RFC 6376].

This library provides both high-level APIs for signing and verifying email
messages, as well as the low-level APIs used to implement this functionality.
It is an asynchronous library based on the Tokio async runtime.

TODO API is experimental, in initial development

The API is being designed with the goal that not the whole message to be
signed/verified must be in memory at once. Instead, messages can be processed in
chunks, and if the necessary amount of chunks has been received can shortcut to
finalisation.

When handling inputs, viadkim is lenient with regard to encoding errors in
inputs. For example, stray Latin 1 bytes in headers pose no problem for this
library, they are handled transparently as byte strings.

The supported signature algorithms, for both signing and verifying, are
`rsa-sha256` and `ed25519-sha256`. The historic signature algorithm `rsa-sha1`
is not supported, and similarly RSA key sizes below 1024 bits are not supported
(see [RFC 8301]).

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
