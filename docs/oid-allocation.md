# GSS-SSHKEY OID Allocation

## Requested Registry

The permanent mechanism OID must be assigned from IANA's "SMI Security for
Mechanism Codes" registry:

```text
iso.org.dod.internet.security.mechanisms (1.3.6.1.5.5)
```

The registry policy is IESG Approval.  An unassigned numeric value, including
the next apparent value, is not available for an implementation to claim.

The Internet-Draft requests this entry:

```text
Value:       TBD1
Name:        sshkey
Description: SSH Public-Key GSS-API Mechanism
Reference:   draft-dowdeswell-kitten-gss-sshkey, Mechanism Identity
```

The registry is maintained at:

<https://www.iana.org/assignments/smi-numbers/>

## Submission Steps

1. Submit the draft through the IETF Datatracker.
2. Request review and adoption by the Kitten working group.
3. Ask the working-group chairs and responsible Security Area Director to
   seek IESG Approval for the `TBD1` assignment.
4. Wait for IANA to record the assigned value before using it in code.

IESG Approval does not require prior RFC publication, but it is exceptional
and normally requires strong community consensus.  The supporting material is
the Internet-Draft, the implementation, and the repeatable interoperability
tests in this repository.

## Draft Validation

The `-00` RFCXML source was checked on 2026-10-06 with `xml2rfc` 3.34.1.  Text,
HTML, expanded XML, and prepped XML all rendered without warnings.  The
official IETF Author Tools validator reported no errors, formatting warnings,
bare Unicode, non-ASCII text, or submission-check nits.  Generated renderings
are build artifacts and are not committed.

Before submission, update the document date and run:

```sh
xml2rfc draft-dowdeswell-kitten-gss-sshkey-00.xml \
  --text --html --expand --preptool --warn-bare-unicode
```

Then upload the RFCXML source to <https://author-tools.ietf.org/> for the
current service-side validation and to <https://datatracker.ietf.org/submit/>
for submission.  A first-submission check may note that it cannot determine
the draft's previous submission date; that warning is expected for `-00`.

## Assignment Checklist

After IANA records the value:

1. Replace `TBD1` and the private experimental OID in the Internet-Draft.
2. Calculate and record the assigned OID's DER contents octets.
3. Replace the OID and DER bytes in the Rust implementation, Makefile, C smoke
   tests, loader configuration, integration adapter, and documentation.
4. Run the complete Rust, GSS loader, installation, packaging, and live
   OpenSSH acceptance suites.
5. Remove the OID item from `TODO.md` only after all replacement checks pass.
