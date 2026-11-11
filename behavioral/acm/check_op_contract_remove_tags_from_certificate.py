"""op-contract-removeTagsFromCertificate."""
from __future__ import annotations

import re
import time

CHECK = "op-contract-removeTagsFromCertificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTagsFromCertificate is value-scoped: removal with the wrong Value leaves the
    tag in place, and only the exact key+value match removes it. A reserved aws:-prefixed
    tag key is rejected with InvalidTagException."""
    acm = ctx.client("acm")
    domain = _unique_domain(ctx, "acmrmtags")
    arn = acm.request_certificate(DomainName=domain, ValidationMethod="DNS")["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))
    _wait_describable(acm, arn)

    acm.add_tags_to_certificate(CertificateArn=arn, Tags=[{"Key": "sim2real-stage", "Value": "prod"}])
    tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]}
    assert tags == {"sim2real-stage": "prod"}

    # removing with the WRONG value must not remove the tag (value-scoped semantics)
    acm.remove_tags_from_certificate(
        CertificateArn=arn, Tags=[{"Key": "sim2real-stage", "Value": "staging"}]
    )
    tags_after_wrong_value = {
        t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]
    }
    assert tags_after_wrong_value == {"sim2real-stage": "prod"}, (
        "tag must survive a remove call carrying a mismatched value"
    )

    # removing with the correct key+value actually removes it
    acm.remove_tags_from_certificate(
        CertificateArn=arn, Tags=[{"Key": "sim2real-stage", "Value": "prod"}]
    )
    assert acm.list_tags_for_certificate(CertificateArn=arn)["Tags"] == []

    # error boundary: a reserved aws:-prefixed tag key is rejected with InvalidTagException
    code, message = _error_code(
        lambda: acm.remove_tags_from_certificate(
            CertificateArn=arn, Tags=[{"Key": "aws:reserved", "Value": "x"}]
        )
    )
    assert code == "InvalidTagException", f"expected InvalidTagException, got {code}"
    assert message == "Invalid Tag Key: \"aws:reserved\". AWS internal tags cannot be changed with this API.", (
        f"expected the exact InvalidTagException message AWS returns, got {message!r}"
    )


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
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
