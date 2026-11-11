"""op-contract-addTagsToCertificate."""
from __future__ import annotations

import re
import time

CHECK = "op-contract-addTagsToCertificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTagsToCertificate: tags land exactly as given; aws:-prefixed tag key is rejected
    and leaves the certificate's tag set unchanged."""
    acm = ctx.client("acm")
    domain = _unique_domain(ctx, "acmtags")
    arn = acm.request_certificate(DomainName=domain, ValidationMethod="DNS")["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))
    _wait_describable(acm, arn)

    # success path: AddTagsToCertificate lands exactly the given key/value pairs
    acm.add_tags_to_certificate(
        CertificateArn=arn,
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "acm-suite"}],
    )
    tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]}
    assert tags.get("sim2real-env") == "test", f"expected sim2real-env=test, got {tags.get('sim2real-env')!r}"
    assert tags.get("sim2real-owner") == "acm-suite", (
        f"expected sim2real-owner=acm-suite, got {tags.get('sim2real-owner')!r}"
    )
    assert len(tags) == 2, f"expected exactly 2 tags landed, got {len(tags)}: {tags!r}"

    # error boundary: a tag key with the reserved "aws:" prefix is rejected with
    # InvalidTagException, and the certificate's tag set is left unchanged (no partial apply)
    code, message = _error_code(
        lambda: acm.add_tags_to_certificate(
            CertificateArn=arn, Tags=[{"Key": "aws:reserved", "Value": "nope"}]
        )
    )
    assert code == "InvalidTagException", f"expected InvalidTagException, got {code}"
    assert message == "Invalid Tag Key: \"aws:reserved\". AWS internal tags cannot be changed with this API.", (
        f"expected the exact InvalidTagException message AWS returns, got {message!r}"
    )
    tags_after = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]}
    assert tags_after == tags, "rejected tag call must not mutate the existing tag set"


def _unique_domain(ctx, label: str) -> str:
    raw = ctx.unique_name(f"{label}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return f"{raw}.example.com"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_describable(acm, arn: str, timeout_s: float = 30.0, interval_s: float = 1.5):
    from botocore.exceptions import ClientError

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
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
