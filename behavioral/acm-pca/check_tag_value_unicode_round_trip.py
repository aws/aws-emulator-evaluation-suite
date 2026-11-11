"""tag-value-unicode-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing unicode text, and a separate tag with an empty-string
    value, set via TagCertificateAuthority, come back exactly unchanged from ListTags."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx, ctx.unique_name("pca-tag-"))

    unicode_key = ctx.unique_name("tag-unicode-")
    empty_key = ctx.unique_name("tag-empty-")
    unicode_value = "café Núñez Zürich Москва 東京 Straße"

    acmpca.tag_certificate_authority(
        CertificateAuthorityArn=ca_arn,
        Tags=[
            {"Key": unicode_key, "Value": unicode_value},
            {"Key": empty_key, "Value": ""},
        ],
    )

    fetched = acmpca.list_tags(CertificateAuthorityArn=ca_arn)["Tags"]
    fetched_by_key = {t["Key"]: t for t in fetched}

    assert unicode_key in fetched_by_key, f"unicode-value tag missing from ListTags: {fetched}"
    assert "Value" in fetched_by_key[unicode_key], (
        f"unicode tag has no Value field at all: {fetched_by_key[unicode_key]!r}"
    )
    assert fetched_by_key[unicode_key]["Value"] == unicode_value, (
        f"unicode tag value changed: sent={unicode_value!r} got={fetched_by_key[unicode_key]['Value']!r}"
    )
    assert empty_key in fetched_by_key, f"empty-value tag missing from ListTags: {fetched}"
    assert "Value" in fetched_by_key[empty_key], (
        f"empty-string tag's Value field was dropped rather than preserved as empty: "
        f"{fetched_by_key[empty_key]!r}"
    )
    assert fetched_by_key[empty_key]["Value"] == "", (
        f"empty-string tag value was not preserved: got={fetched_by_key[empty_key]['Value']!r}"
    )


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


def _create_root_ca(ctx, common_name):
    acmpca = ctx.client("acm-pca")
    config = {
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"Country": "US", "Organization": "Sim2Real Test", "CommonName": common_name[:64]},
    }
    arn = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration=config,
        CertificateAuthorityType="ROOT",
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(
        lambda: acmpca.delete_certificate_authority(
            CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7
        )
    )
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda status: status == "PENDING_CERTIFICATE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
