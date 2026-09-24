# Third-party software and references

AD CS Enrollment Broker depends on third-party software that remains under its own license.
This file describes the inventory boundary; it does not replace the license text
or attribution supplied by each component.

The root `NOTICE` contains the attribution for AD CS Enrollment Broker itself. Dependency
copyright and license notices remain governed by the exact SBOM, license scan,
runtime inventory, and package-provided notice files described below.

## Distributed application dependencies

The locked NuGet graph currently includes
`System.DirectoryServices.Protocols` and
`System.Security.Cryptography.Pkcs`, including their resolved transitive
dependencies. Exact names and versions come from the committed
`packages.lock.json` files. Each protected release produces an SPDX application
SBOM and a license scan for the exact candidate.

The runtime image uses the pinned .NET runtime base and exact native packages
for Kerberos/GSSAPI, LDAP, SASL, credential renewal, and PKCS#11 support. The
release evidence includes the runtime package inventory and binds it to the
image. Consult that evidence and the package-provided copyright files for exact
versions and terms.

CI also uses digest-pinned .NET SDK, secret scanning, static analysis,
dependency scanning, and repository scanning images. These tools build and
assess the project; they are not bundled into the broker application.

Documentation CI uses MkDocs Material 9.6.20 under the MIT license and Mermaid
CLI 11.9.0, whose Mermaid dependency is also MIT licensed. Their container
images are digest pinned, used only to build or validate documentation, and are
not distributed with the broker runtime.

## Protocol references

The public source links to Microsoft Open Specifications and relevant OASIS and
W3C standards. It does not redistribute specification PDFs. Reference
implementations were used only for interoperability research; their source and
history are not included, and their licenses do not apply to original broker
code merely because they were consulted.

Before each release, review the SPDX SBOM and license-scan output, resolve every
unknown or incompatible result, preserve required notices, and update this file
when the dependency boundary changes.

