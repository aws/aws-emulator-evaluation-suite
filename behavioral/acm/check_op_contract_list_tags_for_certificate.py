"""op-contract-listTagsForCertificate."""
from __future__ import annotations

import re
import time

CHECK = "op-contract-listTagsForCertificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForCertificate reflects exactly the tags applied via AddTagsToCertificate
    (no extras, no drops); a malformed ARN is ValidationException."""
    acm = ctx.client("acm")
    domain = _unique_domain(ctx, "acmlisttags")
    arn = acm.request_certificate(DomainName=domain, ValidationMethod="DNS")["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))
    _wait_describable(acm, arn)

    # a freshly requested certificate carries no tags
    fresh = acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]
    assert fresh == [], f"expected no tags on fresh certificate, got {fresh}"

    acm.add_tags_to_certificate(
        CertificateArn=arn,
        Tags=[{"Key": "sim2real-a", "Value": "1"}, {"Key": "sim2real-b", "Value": "2"}],
    )
    tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]}
    assert tags == {"sim2real-a": "1", "sim2real-b": "2"}, f"expected exactly the two added tags, got {tags}"

    # error boundary: a string that is not even shaped like an ARN fails ACM's
    # server-side ARN-shape validation and is rejected with ValidationException
    # (distinct from ResourceNotFoundException, and from InvalidArnException which
    # ACM reserves for ARNs that parse as ARNs but reference the wrong resource
    # type/service). The ARN value must still satisfy the API's minimum-length
    # constraint (20 chars) so that the request actually reaches the service instead
    # of being rejected client-side by botocore.
    code, message = _error_code(lambda: acm.list_tags_for_certificate(CertificateArn="not-an-acm-arn-0123456789"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "1 validation error detected: Value of the input at 'certificateArn' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:[\\w+=/,.@-]+:acm:[\\w+=/,.@-]*:[0-9]+:[\\w+=,.@-]+(/[\\w+=,.@-]+)*", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )


def _unique_domain(ctx, label: str) -> str:
    raw = ctx.unique_name(f"{label}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return f"{raw}.example.com"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to be refused with an error, but it succeeded")


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
