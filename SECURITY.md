# Security Policy

## Security Model

The primary defence is the index and package signatures. If a package
signing key is trusted, it is approved to modify the system. The simplest
attack in these scenarios is to just ship a package installing a backdoor
or modifying the system security controlling files.

For the above reason any attack requiring a signed and trusted package
(or use of *--allow-untrusted* option) typically is *not* a security
issue. If you think there are extenuating circumstances, you can initially
report these as security issues (e.g. normal package build tooling such
as *apk mkpkg* and/or *abuild* produces an incorrect package that misbehaves
at installation time with system wide security implications).

Especially requiring a crafted index or package which is signed and
trusted to trigger the issue is not a security issue. It would be treated
as a normal bug.

## CVSS scoring criteria

If you are suggesting a CVSS score in your report, please consider the
full attack complexity and additional controls that need to be bypassed:
 - even if the actual file change is simple, but the attack relies on
   compromised mirror, or man-in-the-middle attack, set Attack Complexity
   to High (AC:H); or alternatively a repository would need to be injected
   to system configuration meaning Privileges Required is High (PR:H).
 - if a non-repository package would need to be installed or processed,
   it typically either needs User Interaction (UI:R) and/or requires
   compromising a workflow increasing Attack Complexity to High (AC:H)
 - in case of crashes, please consider how reliable it is: not all OOB
   reads cause a crash if the memory is in mapped area. If an actual
   crash cannot be produced reliably or it is dependent on specific
   memory allocator, Availability Impact would typically be Low (A:L).
   If you have not been able to reproduce a crash, it possible that
   you have found a theoretical issue and not an actual exploitable
   security issue.

## Reporting Security issues

Please report a confidential issue in the project GitLab at:
 https://gitlab.alpinelinux.org/alpine/apk-tools/

If you are unwilling to use GitLab for reporting, please reach out
to timo.teras@iki.fi.
