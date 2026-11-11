"""op-contract-describeIpamPolicies."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeIpamPolicies"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamPolicies returns a new policy with its IPAM ID in create-complete, DryRun answers
    DryRunOperation with its exact message, and after delete the policy is absent, deleting or rejected."""
    ec2 = ctx.client("ec2")
    ipam_id = _create_ipam(ctx, ec2)

    policy = ec2.create_ipam_policy(IpamId=ipam_id)["IpamPolicy"]
    policy_id = policy["IpamPolicyId"]
    # The check deletes the policy itself; this teardown covers an early failure and
    # tolerates the delete already being in progress.
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id)))

    def probe():
        resp = ec2.describe_ipam_policies(IpamPolicyIds=[policy_id])
        return resp.get("IpamPolicies", [])

    items = _poll_until(
        probe, lambda v: len(v) == 1 and v[0]["State"] == "create-complete", timeout_s=60.0, interval_s=2.0
    )
    described = items[0]
    assert described["IpamPolicyId"] == policy_id, (
        f"expected IpamPolicyId {policy_id!r}, got {described['IpamPolicyId']!r}"
    )
    assert described["IpamId"] == ipam_id, (
        f"expected policy scoped to IpamId {ipam_id!r}, got {described['IpamId']!r}"
    )
    assert described["State"] == "create-complete", f"unexpected state: {described['State']}"

    code, message = _error(lambda: ec2.describe_ipam_policies(DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"

    ec2.delete_ipam_policy(IpamPolicyId=policy_id)

    def probe_after_delete():
        try:
            found = ec2.describe_ipam_policies(IpamPolicyIds=[policy_id]).get("IpamPolicies", [])
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"])
        if not found:
            return ("absent", None)
        return ("state", found[0]["State"])

    outcome = _poll_until(
        probe_after_delete,
        lambda v: v[0] in ("error", "absent") or v[1] in ("delete-in-progress", "delete-complete"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    kind, detail = outcome
    if kind == "error":
        assert "NotFound" in detail or "Invalid" in detail, (
            f"expected a NotFound-family error from describe_ipam_policies after delete, got {detail!r}"
        )
    elif kind == "state":
        assert detail in ("delete-in-progress", "delete-complete"), (
            f"describe_ipam_policies still reports state {detail!r} after delete_ipam_policy succeeded"
        )


def _create_ipam(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    return ipam_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamPolicyId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
