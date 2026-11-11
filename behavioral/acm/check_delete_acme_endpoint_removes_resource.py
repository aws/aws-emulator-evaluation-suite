"""delete-acme-endpoint-removes-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-acme-endpoint-removes-resource"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteAcmeEndpoint, the endpoint is gone: DescribeAcmeEndpoint on the same ARN
    returns ResourceNotFoundException, it is absent from ListAcmeEndpoints, and a further
    mutation against the dead ARN is rejected rather than resurrecting or silently no-op'ing it."""
    acm = ctx.client("acm")
    name = ctx.unique_name("sim2real-behav-acme-ep-")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": name}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(acm, arn))

    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "ACTIVE", f"endpoint entered {status} instead of ACTIVE"

    acm.delete_acme_endpoint(AcmeEndpointArn=arn)

    expected_message = f"Could not find ACME endpoint {arn}."
    code, message = _poll_until(
        lambda: _endpoint_gone(acm, arn),
        lambda refusal: refusal is not False,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert code == "ResourceNotFoundException", f"unexpected code after delete: {code} ({message!r})"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    assert arn not in _list_acme_endpoint_arns(acm), "deleted endpoint must not appear in ListAcmeEndpoints"

    mutation_code, mutation_message = _error_code(lambda: acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact="NOT_REQUIRED"))
    assert mutation_code == "ResourceNotFoundException", (
        f"UpdateAcmeEndpoint against a deleted ARN should raise ResourceNotFoundException, got {mutation_code}"
    )
    assert mutation_message == expected_message, f"expected message {expected_message!r}, got {mutation_message!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _endpoint_gone(acm, arn):
    """(code, message) once DescribeAcmeEndpoint refuses with ResourceNotFoundException, False while it still reads."""
    from botocore.exceptions import ClientError

    try:
        acm.describe_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise
    return False


def _list_acme_endpoint_arns(acm):
    arns = set()
    next_token = None
    while True:
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = acm.list_acme_endpoints(**kwargs)
        arns.update(e["AcmeEndpointArn"] for e in page.get("AcmeEndpoints", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    return arns


def _delete_ignoring_not_found(acm, arn):
    from botocore.exceptions import ClientError

    try:
        acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
