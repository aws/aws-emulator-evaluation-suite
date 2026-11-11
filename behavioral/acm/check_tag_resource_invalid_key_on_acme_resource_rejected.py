"""tag-resource-invalid-key-on-acme-resource-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-on-acme-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on an ACME endpoint with a tag key outside the allowed charset is refused with
    ValidationException and the exact pattern message and persists nothing, while a well-formed
    tag on the same endpoint is applied."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)

    bad_key = "invalid#key!"
    code, message = _client_error(
        lambda: acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": bad_key, "Value": "x"}])
    )
    assert code == "ValidationException", f"expected ValidationException for tag key {bad_key!r}, got {code!r}"
    expected = (
        "1 validation error detected: Value of the input at 'tags.1.member.key' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        r"([\p{L}\p{Z}\p{N}_.:/=+\-@]*)"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    tags_after_reject = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    assert all(t["Key"] != bad_key for t in tags_after_reject), (
        f"rejected tag key {bad_key!r} was persisted anyway: {tags_after_reject!r}"
    )

    good_key = ctx.unique_name("sim2real-tag-")
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": good_key, "Value": "ok"}])
    tags_after_accept = acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    assert any(t["Key"] == good_key and t["Value"] == "ok" for t in tags_after_accept), (
        f"expected well-formed tag {good_key!r}=ok to be visible, got {tags_after_accept!r}"
    )


def _client_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _delete_endpoint(ctx, arn: str) -> None:
    """Teardown: delete the endpoint, retrying the documented ConflictException while it is still
    settling; an endpoint that is already gone is accepted, anything else raises."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + min(120.0, ctx.time_left() or 120.0)
    while True:
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
