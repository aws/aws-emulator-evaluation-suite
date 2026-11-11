"""acme-endpoint-full-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-endpoint-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeEndpoint produces a resource visible via Describe/List, mutable via Update, removable via Delete."""
    acm = ctx.client("acm")
    name = ctx.unique_name("sim2real-behav-acme-ep-")

    created = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": name}],
    )
    arn = created["AcmeEndpointArn"]
    assert arn.startswith("arn:aws:acm:") and ":acme-endpoint/" in arn
    ctx.on_cleanup(lambda: _best_effort_delete_endpoint(acm, arn))

    # Immediately visible via Describe, in a non-terminal-failure state.
    desc = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert desc["AcmeEndpointArn"] == arn
    assert desc["Status"] in ("CREATING", "ACTIVE")
    assert desc["AuthorizationBehavior"] == "PRE_APPROVED"
    assert desc["CertificateAuthority"] == {"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}}
    assert desc["Contact"] == "NOT_REQUIRED"

    # Visible via List.
    found = _find_endpoint(acm, arn)
    assert found is not None, "created endpoint not present in ListAcmeEndpoints"

    # Reaches ACTIVE.
    active = _wait_for_status(acm, arn, {"ACTIVE", "FAILED"}, timeout_s=90)
    assert active == "ACTIVE", f"endpoint did not reach ACTIVE, got {active}"

    # Mutable via Update: flip Contact requirement.
    acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact="REQUIRED")
    desc2 = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    assert desc2["Contact"] == "REQUIRED"
    assert desc2["Status"] == "ACTIVE", "update must not disturb ACTIVE status"

    # Removable via Delete.
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    removed_code, removed_message = _poll_until_removed(acm, arn, timeout_s=60)
    assert removed_code == "ResourceNotFoundException", (
        f"Describe on the deleted endpoint should fail with ResourceNotFoundException, got {removed_code}"
    )
    expected_message = f"Could not find ACME endpoint {arn}."
    assert removed_message == expected_message, f"expected message {expected_message!r}, got {removed_message!r}"

    # Gone from List too, not just from Describe.
    assert _find_endpoint(acm, arn) is None, "deleted endpoint still appears in ListAcmeEndpoints"

    # A mutation on the dead id also fails with the same specific not-found code.
    mutate_code, mutate_message = _error_code(
        lambda: acm.update_acme_endpoint(AcmeEndpointArn=arn, Contact="NOT_REQUIRED")
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"UpdateAcmeEndpoint on deleted endpoint should fail with ResourceNotFoundException, got {mutate_code}"
    )
    assert mutate_message == expected_message, f"expected message {expected_message!r}, got {mutate_message!r}"


def _find_endpoint(acm, arn):
    paginator_kwargs = {}
    while True:
        resp = acm.list_acme_endpoints(**paginator_kwargs)
        for ep in resp.get("AcmeEndpoints", []):
            if ep.get("AcmeEndpointArn") == arn:
                return ep
        token = resp.get("NextToken")
        if not token:
            return None
        paginator_kwargs = {"NextToken": token}


def _wait_for_status(acm, arn, terminal_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    return last


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_removed(acm, arn, timeout_s=60.0, interval_s=2.0):
    """Poll Describe until it is refused; return the refusal's (code, message)."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} was not removed after DeleteAcmeEndpoint (last status={last_status!r})")


def _best_effort_delete_endpoint(acm, arn):
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
