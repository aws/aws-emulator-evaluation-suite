"""op-contract-delete-ipam-policy."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-ipam-policy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamPolicy deletes a new IPAM policy, which DescribeIpamPolicies then fails with
    InvalidIpamPolicyId.NotFound; deleting it again and deleting an unknown policy ID fail with the same
    code (exact messages)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ipampolicy-")

    ipam = ec2.create_ipam(Description=name)["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True)))

    policy = ec2.create_ipam_policy(
        IpamId=ipam_id,
        TagSpecifications=[{"ResourceType": "ipam-policy", "Tags": [{"Key": "Name", "Value": name}]}],
    )["IpamPolicy"]
    policy_id = policy["IpamPolicyId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id)))

    resp = ec2.delete_ipam_policy(IpamPolicyId=policy_id)
    deleted = resp["IpamPolicy"]
    assert deleted["IpamPolicyId"] == policy_id, f"expected {policy_id!r}, got {deleted['IpamPolicyId']!r}"
    assert deleted["State"] in ("delete-in-progress", "delete-complete"), (
        f"expected delete-in-progress/delete-complete, got {deleted['State']!r}"
    )

    # Independent read at the destination: a DescribeIpamPolicies call (not the delete's own
    # response) must report the policy gone. AWS raises InvalidIpamPolicyId.NotFound rather
    # than returning an empty list or a terminal state.
    def probe():
        try:
            ec2.describe_ipam_policies(IpamPolicyIds=[policy_id])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return None

    describe_code, describe_message = _poll_until(probe, lambda e: e is not None, timeout_s=30.0, interval_s=2.0)
    assert describe_code == "InvalidIpamPolicyId.NotFound", f"unexpected code from an independent Describe {describe_code!r}"
    assert describe_message == f"The IPAM policy ID ({policy_id}) does not exist.", f"unexpected message {describe_message!r}"

    # A mutation on the now-dead id also fails: the id this check itself deleted is unusable.
    code, message = _error(lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id))
    assert code == "InvalidIpamPolicyId.NotFound", f"unexpected code deleting the already-deleted policy {code!r}"
    assert message == f"The ipam-policy ID '{policy_id}' does not exist", f"unexpected message {message!r}"

    # Error boundary: deleting an entirely unknown IPAM policy ID is also rejected.
    fake_id = _zeroed_id(policy_id)
    code2, message2 = _error(lambda: ec2.delete_ipam_policy(IpamPolicyId=fake_id))
    assert code2 == "InvalidIpamPolicyId.NotFound", f"unexpected code {code2!r}"
    assert message2 == f"The ipam-policy ID '{fake_id}' does not exist", f"unexpected message {message2!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidIpamId.NotFound",
            "InvalidIpamPolicyId.NotFound",
        ):
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
