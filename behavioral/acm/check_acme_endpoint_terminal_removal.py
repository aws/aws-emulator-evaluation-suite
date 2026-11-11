"""acme-endpoint-terminal-removal."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-endpoint-terminal-removal"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteAcmeEndpoint succeeds, DescribeAcmeEndpoint on the same identifier returns ResourceNotFoundException."""
    acm = ctx.client("acm")
    name = ctx.unique_name("sim2real-behav-acme-ep-")

    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": name}],
    )["AcmeEndpointArn"]
    cleanup_state = {"deleted": False}

    def _cleanup():
        if not cleanup_state["deleted"]:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)

    ctx.on_cleanup(_cleanup)

    # Positive control: the resource is describable while it exists.
    desc = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert desc["AcmeEndpointArn"] == arn, f"expected describe to echo {arn}, got {desc.get('AcmeEndpointArn')!r}"

    status = _wait_for_status(acm, arn, {"ACTIVE", "FAILED"}, timeout_s=90)
    assert status == "ACTIVE", f"endpoint {arn} settled in {status!r} instead of ACTIVE"

    acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    cleanup_state["deleted"] = True

    code, message = _poll_for_error_code(lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn), timeout_s=60)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Could not find ACME endpoint {arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The forbidden effect (a describable resource) is absent: List no longer contains it either.
    assert _find_endpoint(acm, arn) is None, "deleted endpoint still appears in ListAcmeEndpoints"


def _wait_for_status(acm, arn, terminal_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {terminal_statuses} within {timeout_s}s, last status={last!r}")


def _poll_for_error_code(fn, timeout_s=60.0, interval_s=2.0):
    """Poll fn() until it is refused; return the refusal's (code, message), raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call kept succeeding for {timeout_s}s after the delete")


def _find_endpoint(acm, arn):
    kwargs = {}
    while True:
        resp = acm.list_acme_endpoints(**kwargs)
        for ep in resp.get("AcmeEndpoints", []):
            if ep.get("AcmeEndpointArn") == arn:
                return ep
        token = resp.get("NextToken")
        if not token:
            return None
        kwargs = {"NextToken": token}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
