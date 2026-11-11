"""op-contract-describeIpamPools."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeIpamPools"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamPools returns a new ipv6 pool in its scope by ID and under an ipam-scope-id filter, and
    DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    # Cascade deletes the scope and the pool with the IPAM; deleting the scope on its
    # own fails while the pool delete is still in progress.
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    scope = ec2.create_ipam_scope(IpamId=ipam_id)["IpamScope"]
    scope_id = scope["IpamScopeId"]

    pool = ec2.create_ipam_pool(IpamScopeId=scope_id, AddressFamily="ipv6")["IpamPool"]
    pool_id = pool["IpamPoolId"]

    def by_id():
        resp = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])
        return resp.get("IpamPools", [])

    # A new pool can lack attributes such as IpamScopeArn until it reaches create-complete, so poll for
    # that state (the pool item carries IpamScopeArn, not IpamScopeId); pool creation can take longer
    # than 60 s.
    items = _poll_until(
        by_id,
        lambda v: len(v) == 1 and v[0].get("State") == "create-complete" and "IpamScopeArn" in v[0],
        timeout_s=180.0,
        interval_s=5.0,
    )
    described = items[0]
    assert described["IpamPoolId"] == pool_id, (
        f"expected pool id {pool_id}, got {described['IpamPoolId']}"
    )
    assert described["IpamScopeArn"].endswith(scope_id), (
        f"expected scope {scope_id} in arn, got {described['IpamScopeArn']}"
    )
    assert described["AddressFamily"] == "ipv6", (
        f"expected address family ipv6, got {described['AddressFamily']}"
    )

    filtered = ec2.describe_ipam_pools(
        Filters=[{"Name": "ipam-scope-id", "Values": [scope_id]}]
    )["IpamPools"]
    assert any(p["IpamPoolId"] == pool_id for p in filtered), (
        "pool not found when filtering by its owning scope"
    )

    code, message = _error(lambda: ec2.describe_ipam_pools(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
