"""create-ca-subject-field-contract-limits-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-ca-subject-field-contract-limits-rejected"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

# Constraints read directly out of the acm-pca Smithy model, ASN1Subject members:
#   Country              CountryCodeString      length 2..2, pattern ^[A-Za-z]{2}$
#   CommonName           String64               length 0..64
#   GenerationQualifier  String3                length 0..3
#   CustomAttributes[].ObjectIdentifier  CustomObjectIdentifier
#                        pattern ^([0-2])\.([0-9]|([0-3][0-9]))((\.([0-9]+)){0,126})$
# All four are server-side: botocore validates only {'required','min','document','union'},
# so `max` length and `pattern` are never enforced client-side. Country's `min` IS 2, and
# "USA" is 3 characters, so it satisfies min and reaches the service.
_COMMON_NAME_MAX = 64
_GENERATION_QUALIFIER_MAX = 3

# CreateCertificateAuthority models only InvalidArgsException / InvalidPolicyException /
# InvalidTagException / LimitExceededException, but a Smithy CONSTRAINT violation never
# reaches the service logic: it is refused by the frontend with the UNMODELED generic
# ValidationException, whose message names the exact member path and the exact bound. The
# modeled codes are for semantic defects that pass constraint validation (the control below
# is refused with InvalidTagException for a reserved tag prefix). Because all four breaks
# therefore share one code, each additionally asserts the member path in the message -- a
# bare ValidationException would otherwise let one generic refusal satisfy all four.
_EXPECTED_SUBJECT_REJECTION = "ValidationException"

# ===== helpers (self-contained) =====


def _err(fn, ctx):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. The
    message carries which subject member was refused, which is the only thing
    distinguishing these four breaks on real AWS. An unexpected success registers the
    created authority for deletion and raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message") or ""
    arn = (result or {}).get("CertificateAuthorityArn")
    if arn:
        ctx.on_cleanup(lambda: ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
        ))
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and created {arn!r}")


def _retrying(fn):
    for attempt in range(6):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    raise AssertionError("unreachable")


def _subjects(pca):
    """Every CommonName and every SerialNumber currently present in the account's CA
    subjects, including soft-DELETED authorities."""
    seen = set()
    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        for ca in page.get("CertificateAuthorities", []):
            subj = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {})
            for key in ("CommonName", "SerialNumber"):
                if subj.get(key):
                    seen.add(subj[key])
    return seen


def _ca_body(subject, tag_list=None):
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": subject,
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
    }
    if tag_list is not None:
        body["Tags"] = tag_list
    return body


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthority validates the ASN1Subject against its X.500 constraints: a
    3-letter Country, a 65-char CommonName, a 4-char GenerationQualifier and an out-of-range OID
    arc are each refused, while a legal subject is refused only for a separate tag defect."""
    pca = ctx.client("acm-pca")
    marker = ctx.unique_name("sim2real-behav-pca-subj-").rstrip("-")

    # Break A -- Country outside CountryCodeString (length 2..2, ^[A-Za-z]{2}$).
    cn_a = marker + "-a"
    code_a, msg_a = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body({"CommonName": cn_a, "Country": "USA"})
    )), ctx)
    assert code_a == _EXPECTED_SUBJECT_REJECTION, (
        f"Country='USA' is three characters where the model allows exactly two and must "
        f"be refused with {_EXPECTED_SUBJECT_REJECTION}, got {code_a!r}"
    )
    assert msg_a == (
        "2 validation errors detected: Value at "
        "'certificateAuthorityConfiguration.subject.country' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [A-Za-z]{2}; Value at "
        "'certificateAuthorityConfiguration.subject.country' failed to satisfy constraint: "
        "Member must have length less than or equal to 2"
    ), (
        f"the refusal must name the offending member certificateAuthorityConfiguration."
        f"subject.country and the 2-character CountryCodeString bound, got {msg_a!r}"
    )

    # Break B -- CommonName one character over String64.
    over_cn = "c" * (_COMMON_NAME_MAX + 1)
    code_b, msg_b = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body({"CommonName": over_cn})
    )), ctx)
    assert code_b == _EXPECTED_SUBJECT_REJECTION, (
        f"a {_COMMON_NAME_MAX + 1}-character CommonName exceeds the modeled maximum of "
        f"{_COMMON_NAME_MAX} and must be refused with {_EXPECTED_SUBJECT_REJECTION}, "
        f"got {code_b!r}"
    )
    assert msg_b == (
        "1 validation error detected: Value at "
        "'certificateAuthorityConfiguration.subject.commonName' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_COMMON_NAME_MAX}"
    ), (
        f"the refusal must name subject.commonName and the {_COMMON_NAME_MAX}-character "
        f"bound, got {msg_b!r}"
    )
    assert msg_b != msg_a, (
        f"an over-long CommonName and a 3-letter Country are different violations but "
        f"produced the identical diagnostic {msg_a!r}"
    )

    # Break C -- GenerationQualifier one character over String3. A deliberately obscure
    # field: an emulator that special-cases only CommonName misses it.
    cn_c = marker + "-c"
    code_c, msg_c = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body({
            "CommonName": cn_c,
            "GenerationQualifier": "q" * (_GENERATION_QUALIFIER_MAX + 1),
        })
    )), ctx)
    assert code_c == _EXPECTED_SUBJECT_REJECTION, (
        f"a {_GENERATION_QUALIFIER_MAX + 1}-character GenerationQualifier exceeds the "
        f"modeled maximum of {_GENERATION_QUALIFIER_MAX} and must be refused with "
        f"{_EXPECTED_SUBJECT_REJECTION}, got {code_c!r}"
    )
    assert msg_c == (
        "1 validation error detected: Value at "
        "'certificateAuthorityConfiguration.subject.generationQualifier' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_GENERATION_QUALIFIER_MAX}"
    ), (
        f"the refusal must name subject.generationQualifier and its "
        f"{_GENERATION_QUALIFIER_MAX}-character bound -- an implementation that special-cases "
        f"only commonName cannot produce this -- got {msg_c!r}"
    )

    # Break D -- a CustomAttributes ObjectIdentifier whose first arc is 9. The model's
    # pattern pins the first arc to ^([0-2]), because ITU/ISO OID arcs 0-2 are the only
    # ones that exist; "9.9.9" is not an OID at all.
    cn_d = marker + "-d"
    code_d, msg_d = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body({
            "CommonName": cn_d,
            "CustomAttributes": [{"ObjectIdentifier": "9.9.9", "Value": "x"}],
        })
    )), ctx)
    assert code_d == _EXPECTED_SUBJECT_REJECTION, (
        f"CustomAttributes ObjectIdentifier '9.9.9' has a first arc outside 0-2 and must "
        f"be refused with {_EXPECTED_SUBJECT_REJECTION}, got {code_d!r}"
    )
    assert msg_d == (
        "1 validation error detected: Value at "
        "'certificateAuthorityConfiguration.subject.customAttributes.1.member.objectIdentifier' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        r"([0-2])\.([0-9]|([0-3][0-9]))((\.([0-9]+)){0,126})"
    ), (
        f"the refusal must name the indexed customAttributes objectIdentifier member and the "
        f"OID arc pattern it violated, got {msg_d!r}"
    )

    # Control -- a fully legal, richly populated subject (every field within its modeled
    # bound, a valid two-letter Country, a well-formed OID) plus exactly one non-subject
    # defect: a reserved 'aws:' tag key. The request must be refused for the TAG. If it
    # returns the subject code instead, the emulator rejects any subject it did not expect
    # and Breaks A-D proved nothing.
    #
    # A control that creates the CA with this legal subject would mint a metered private CA,
    # so the legal subject is refused only for its reserved tag prefix.
    cn_ctl = marker + "-ctl"
    code_ctl, msg_ctl = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(
            {
                "CommonName": cn_ctl,
                "Country": "US",
                "Organization": "sim2real",
                "OrganizationalUnit": "testing",
                "State": "Washington",
                "Locality": "Seattle",
                "GenerationQualifier": "III",
                "CustomAttributes": [{"ObjectIdentifier": "2.5.4.3", "Value": "x"}],
            },
            tag_list=[{"Key": "aws:reserved", "Value": "x"}],
        )
    )), ctx)
    assert code_ctl == "InvalidTagException", (
        f"a fully legal subject must get past subject validation and be refused for its "
        f"reserved tag key (InvalidTagException), got {code_ctl!r}"
    )
    assert msg_ctl == (
        "Tags starting with 'aws' are categorized as AWS internal tags and cannot be used "
        "for tagging in ACM Private CA service."
    ), (
        f"the control's refusal must be about the reserved 'aws' tag prefix and must name no "
        f"subject member, got {msg_ctl!r}"
    )
    assert code_ctl != code_a, (
        f"the legal-subject control and the bad-Country case returned the same code "
        f"({code_a!r}); subject fields are not being validated individually"
    )

    # Effect absent -- none of the five refused requests left an authority behind.
    seen = _subjects(pca)
    for cn in (cn_a, over_cn, cn_c, cn_d, cn_ctl):
        assert cn not in seen, (
            f"a refused CreateCertificateAuthority still produced an authority whose "
            f"subject carries {cn!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
