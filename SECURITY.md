# Security

The decoder reads archives from untrusted sources, and archives can be encrypted. We take
problems in both seriously.

## Reporting a vulnerability

Please do **not** open a public issue. Report it privately through GitHub:
*Security* tab of this repository › *Report a vulnerability*
(<https://github.com/solitdr/archydes/security/advisories/new>).

Please include the version (`archydes --version`), what happens and, if you can, an archive
that shows it. We confirm within a few working days and keep you informed until it is fixed.

## Scope

- The reference decoder and the `archydes` tool: crashes, hangs, excessive memory use, writing
  outside the target folder (path traversal, symlinks), restoring set-id bits.
- The encryption scheme (SPEC A11) and its implementation: anything that reveals content, names
  or keys without the password, or lets an archive be changed unnoticed.
- Mistakes in the specification that make secure implementations hard.

## Supported versions

Fixes go into the newest release.
