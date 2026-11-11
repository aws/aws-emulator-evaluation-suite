"""acme-endpoint-delete-then-describe-404."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "acme-endpoint-delete-then-describe-404"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an ACME endpoint then describing it fails with ResourceNotFoundException,
    not a stale copy of the deleted config."""
    acm = ctx.client("acm")
    name = ctx.unique_name("sim2real-behav-acme-ep-")

    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": name}],
    )["AcmeEndpointArn"]
    cleaned = {"done": False}

    def _cleanup():
        if not cleaned["done"]:
            from botocore.exceptions import ClientError
            try:
                acm.delete_acme_endpoint(AcmeEndpointArn=arn)
            except ClientError as err:
                # ResourceNotFoundException here just means it is already gone -- fine.
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    _poll_until_active(ctx, arn)

    acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    cleaned["done"] = True  # the explicit delete above already ran; cleanup is now a no-op safety net

    final_code, final_message = _poll_until_not_found(ctx, arn)
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {final_code!r}"
    )
    expected_message = f"Could not find ACME endpoint {arn}."
    assert final_message == expected_message, f"expected message {expected_message!r}, got {final_message!r}"

    # A mutation on the dead id must also fail -- not just the read. UpdateAcmeEndpoint
    # models ResourceNotFoundException explicitly (unlike DeleteAcmeEndpoint, which is
    # idempotent and may no-op on an already-deleted arn instead of erroring).
    update_code, update_message = _error_code(lambda: acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact="REQUIRED"))
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateAcmeEndpoint on the deleted endpoint to fail with "
        f"ResourceNotFoundException, got {update_code!r}"
    )
    assert update_message == expected_message, f"expected message {expected_message!r}, got {update_message!r}"

    # The endpoint must also be gone from ListAcmeEndpoints, not lingering.
    listed_arns = set()
    next_token = None
    while True:
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = acm.list_acme_endpoints(**kwargs)
        listed_arns.update(e["AcmeEndpointArn"] for e in page.get("AcmeEndpoints", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert arn not in listed_arns, "deleted endpoint must not appear in ListAcmeEndpoints"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_active(ctx, arn, timeout_s=120.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if last["Status"] == "ACTIVE":
            return last
        if last["Status"] == "FAILED":
            raise AssertionError(f"endpoint {arn} reached FAILED: {last.get('FailureReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached ACTIVE, last status={last and last['Status']}")


def _poll_until_not_found(ctx, arn, timeout_s=90.0, interval_s=3.0):
    """Polls Describe until it is refused; returns the refusal's (code, message) and raises if
    the deadline passes while the endpoint is still describable."""
    from botocore.exceptions import ClientError
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never disappeared, last observed status={last_status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
