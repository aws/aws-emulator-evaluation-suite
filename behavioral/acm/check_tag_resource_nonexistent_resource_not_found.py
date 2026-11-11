"""tag-resource-nonexistent-resource-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTagsToCertificate and ListTagsForCertificate on a nonexistent certificate ARN are refused
    with ResourceNotFoundException and the exact message, while the same pair on a real
    certificate applies and lists the tag."""
    acm = ctx.client("acm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:acm:{ctx.region}:{account_id}:certificate/"
        "00000000-0000-0000-0000-000000000000"
    )

    expected = f"Could not find certificate {bogus_arn}."
    code, message = _client_error(
        lambda: acm.add_tags_to_certificate(
            CertificateArn=bogus_arn, Tags=[{"Key": "k", "Value": "v"}]
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The nonexistent resource must not have been mutated into existing (still not listable).
    code2, message2 = _client_error(lambda: acm.list_tags_for_certificate(CertificateArn=bogus_arn))
    assert code2 == "ResourceNotFoundException", (
        f"expected the bogus resource to remain absent, got {code2}"
    )
    assert message2 == expected, f"expected {expected!r}, got {message2!r}"

    # Positive control: the same pair works on a real certificate, so a target that refuses
    # every AddTagsToCertificate call cannot pass.
    real_arn = acm.request_certificate(
        DomainName=ctx.unique_name("tag-nf-").lower() + ".example.com",
        ValidationMethod="DNS",
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, real_arn))
    _wait_describable(acm, real_arn)

    acm.add_tags_to_certificate(CertificateArn=real_arn, Tags=[{"Key": "k", "Value": "v"}])
    real_tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=real_arn)["Tags"]}
    assert real_tags.get("k") == "v", f"tag not applied to real certificate: {real_tags}"


def _client_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


def _wait_describable(acm, arn: str, timeout_s: float = 30.0, interval_s: float = 1.5):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return acm.describe_certificate(CertificateArn=arn)["Certificate"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate {arn} never became describable: {last_exc}")


def _safe_delete(acm, arn: str) -> None:
    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
