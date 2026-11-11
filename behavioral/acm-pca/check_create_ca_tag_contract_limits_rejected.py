"""create-ca-tag-contract-limits-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-ca-tag-contract-limits-rejected"
GROUP = 'tags'
SERVICES = ['acm-pca']

# Contract limits read directly out of the acm-pca Smithy model
# (models/acm-pca/service/2017-08-22): TagKey length 1..128, TagValue length 0..256,
# TagList length 1..50, TagKey/TagValue pattern ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$.
# All four are server-side: botocore's VALIDATED_METADATA_ATTRS is
# {'required','min','document','union'}, so neither `max` nor `pattern` is enforced
# client-side and every case below reaches the service.
_TAG_KEY_MAX = 128
_TAG_VALUE_MAX = 256
_TAG_LIST_MAX = 50

# On AWS, InvalidTagException is returned for a SEMANTIC tag defect, but the length/charset/count
# limits are NOT that stage: they are Smithy constraints, refused by the frontend before the service
# sees the request, with the unmodeled generic ValidationException naming the exact member path and
# bound ("Value at 'tags.1.member.key' failed to satisfy constraint: Member must have length less
# than or equal to 128"). So the modeled tag error is not reachable from a contract-limit violation
# at all, and the four breaks share one code -- each therefore also asserts the member path and the
# bound out of the message, which is what keeps them distinguishable.
_EXPECTED_TAG_REJECTION = "ValidationException"
# Same stage, same code: CreateCertificateAuthority does not model TooManyTagsException
# (only TagCertificateAuthority does), and the 51-element list is refused as a TagList
# length constraint.
_EXPECTED_TAG_COUNT_REJECTION = "ValidationException"

# ===== helpers (self-contained) =====


def _err(fn, ctx):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. The
    message names which tag member broke which bound, and on real AWS that is the only
    thing that distinguishes these four breaks from each other. An unexpected success
    registers the created authority for deletion and raises."""
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


def _common_names(pca):
    names = set()
    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        for ca in page.get("CertificateAuthorities", []):
            cn = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {}).get("CommonName")
            if cn:
                names.add(cn)
    return names


def _ca_body(common_name, tag_list=None, signing_algorithm="SHA256WITHRSA"):
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": signing_algorithm,
            "Subject": {"CommonName": common_name},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
    }
    if tag_list is not None:
        body["Tags"] = tag_list
    return body


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthority enforces the tag limits server-side: a 129-char key, a 257-char
    value, a key outside the allowed characters and a 51-tag list are each refused and no CA is
    created, while a non-tag defect on the same body yields a different code."""
    pca = ctx.client("acm-pca")
    marker = ctx.unique_name("sim2real-behav-pca-tagl-").rstrip("-")
    cn_key, cn_val, cn_chr, cn_cnt, cn_ctl = (
        marker + s for s in ("-key", "-val", "-chr", "-cnt", "-ctl")
    )

    # Break A -- key one character over the modeled maximum.
    over_key = "k" * (_TAG_KEY_MAX + 1)
    code_key, msg_key = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(cn_key, tag_list=[{"Key": over_key, "Value": "v"}])
    )), ctx)
    assert code_key == _EXPECTED_TAG_REJECTION, (
        f"a {_TAG_KEY_MAX + 1}-character tag key exceeds the modeled maximum of "
        f"{_TAG_KEY_MAX} and must be refused with {_EXPECTED_TAG_REJECTION}, "
        f"got {code_key!r}"
    )
    assert msg_key == (
        "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_TAG_KEY_MAX}"
    ), (
        f"the refusal must name the tag KEY member and the {_TAG_KEY_MAX}-character bound it "
        f"violated, got {msg_key!r}"
    )

    # Break B -- value one character over the modeled maximum.
    over_value = "v" * (_TAG_VALUE_MAX + 1)
    code_val, msg_val = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(cn_val, tag_list=[{"Key": "sim2real", "Value": over_value}])
    )), ctx)
    assert code_val == _EXPECTED_TAG_REJECTION, (
        f"a {_TAG_VALUE_MAX + 1}-character tag value exceeds the modeled maximum of "
        f"{_TAG_VALUE_MAX} and must be refused with {_EXPECTED_TAG_REJECTION}, "
        f"got {code_val!r}"
    )
    assert msg_val == (
        "1 validation error detected: Value at 'tags.1.member.value' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_TAG_VALUE_MAX}"
    ), (
        f"the refusal must name the tag VALUE member and the {_TAG_VALUE_MAX}-character "
        f"bound, got {msg_val!r}"
    )
    assert msg_val != msg_key, (
        f"an over-long value and an over-long key are different violations but produced the "
        f"identical diagnostic {msg_key!r}"
    )

    # Break C -- a key with a character outside ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$.
    # '!' is not in the class; length and count are both legal here, so the charset rule is
    # the only thing broken.
    code_chr, msg_chr = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(cn_chr, tag_list=[{"Key": "sim2real!key", "Value": "v"}])
    )), ctx)
    assert code_chr == _EXPECTED_TAG_REJECTION, (
        f"a tag key containing '!' is outside the modeled character class and must be "
        f"refused with {_EXPECTED_TAG_REJECTION}, got {code_chr!r}"
    )
    assert msg_chr == (
        "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"([\p{L}\p{Z}\p{N}_.:/=+\-@]*)"
    ), (
        f"the charset refusal must name the tag key member and the pattern it violated -- not "
        f"a length bound -- got {msg_chr!r}"
    )

    # Break D -- one element over the modeled TagList maximum. Every individual tag here
    # is legal, so the list length is the only thing broken.
    too_many = [{"Key": f"sim2real{i}", "Value": "v"} for i in range(_TAG_LIST_MAX + 1)]
    code_cnt, msg_cnt = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(cn_cnt, tag_list=too_many)
    )), ctx)
    assert code_cnt == _EXPECTED_TAG_COUNT_REJECTION, (
        f"{_TAG_LIST_MAX + 1} tags exceeds the modeled TagList maximum of "
        f"{_TAG_LIST_MAX} and must be refused with {_EXPECTED_TAG_COUNT_REJECTION}, "
        f"got {code_cnt!r}"
    )
    assert msg_cnt == (
        "1 validation error detected: Value at 'tags' failed to satisfy constraint: "
        f"Member must have length less than or equal to {_TAG_LIST_MAX}"
    ), (
        f"the count refusal must name the tags LIST itself and the {_TAG_LIST_MAX}-element "
        f"bound, not a member, got {msg_cnt!r}"
    )

    # Control -- exactly {_TAG_LIST_MAX} legal tags (so the tag block is entirely within
    # contract) plus one non-tag defect: an RSA key with an ECDSA signing algorithm. The
    # request must be refused for the ALGORITHM, not the tags. If this returns the tag code
    # instead, the emulator rejects any large tag list regardless of the limit and Break D
    # proved nothing.
    #
    # This substitutes for a positive control: 50 legal tags accepted, the CA created and
    # ListTags showing 50 would mint a metered private CA.
    at_limit = [{"Key": f"sim2real{i}", "Value": "v"} for i in range(_TAG_LIST_MAX)]
    code_ctl, msg_ctl = _err(lambda: _retrying(lambda: pca.create_certificate_authority(
        **_ca_body(cn_ctl, tag_list=at_limit, signing_algorithm="SHA256WITHECDSA")
    )), ctx)
    assert code_ctl == "InvalidArgsException", (
        f"{_TAG_LIST_MAX} tags are within contract, so this request must be refused for "
        f"its RSA/ECDSA algorithm mismatch (InvalidArgsException), got {code_ctl!r}"
    )
    assert msg_ctl == (
        "Signing algorithm SHA256WITHECDSA cannot be used with key type RSA_2048. "
        "Valid signing algorithms are: SHA256WITHRSA, SHA384WITHRSA, SHA512WITHRSA, "
        "SHA256WITHRSA_PSS, SHA384WITHRSA_PSS, SHA512WITHRSA_PSS."
    ), (
        f"the control's refusal must name the mismatched signing algorithm and key type, not "
        f"the tags, got {msg_ctl!r}"
    )
    assert code_ctl != code_cnt, (
        f"the at-limit control and the over-limit case returned the same code "
        f"({code_cnt!r}); the tag-count limit is not being enforced as its own rule"
    )

    # Effect absent -- none of the five refused requests left an authority behind.
    names = _common_names(pca)
    for cn in (cn_key, cn_val, cn_chr, cn_cnt, cn_ctl):
        assert cn not in names, (
            f"a refused CreateCertificateAuthority still produced an authority with "
            f"CommonName={cn!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
