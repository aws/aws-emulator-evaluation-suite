"""describe-nonexistent-acme-endpoint-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-acme-endpoint-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAcmeEndpoint on a well-formed but unknown endpoint ARN raises ResourceNotFoundException,
    while an identical call against a real endpoint still succeeds — proving the rejection is keyed on
    the ARN, not on the operation being refused outright."""
    acm = ctx.client("acm")
    account = _account_id(ctx)

    # Positive control: a real endpoint describes successfully on this same wiring.
    endpoint_arn = _create_acme_endpoint(ctx)
    live = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
    assert live["AcmeEndpointArn"] == endpoint_arn, live

    # Matches the documented pattern arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:acme-endpoint/[a-zA-Z0-9-]+
    fake_arn = f"arn:aws:acm:{ctx.region}:{account}:acme-endpoint/{uuid.uuid4()}"

    code, message = _error(lambda: acm.describe_acme_endpoint(AcmeEndpointArn=fake_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for unknown ACME endpoint, got {code!r}"
    )
    expected_message = f"Could not find ACME endpoint {fake_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_acme_endpoint(ctx) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    endpoint_arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_quiet(ctx, endpoint_arn))
    return endpoint_arn


def _delete_endpoint_quiet(ctx, endpoint_arn: str) -> None:
    acm = ctx.client("acm")
    deadline = time.monotonic() + 30
    while True:
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
