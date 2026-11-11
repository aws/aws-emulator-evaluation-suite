"""op-contract-delete-public-ipv4-pool."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-public-ipv4-pool"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePublicIpv4Pool deletes an empty owned pool, which DescribePublicIpv4Pools then fails with
    InvalidPublicIpv4PoolID.NotFound; a repeat delete of that ID and deletes of pool IDs never owned
    are rejected, and a not-found answer carries the exact message naming the ID."""
    ec2 = ctx.client("ec2")
    pool_id = ec2.create_public_ipv4_pool(
        TagSpecifications=[
            {
                "ResourceType": "ipv4pool-ec2",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-pubpool-")}],
            }
        ]
    )["PoolId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            ec2.delete_public_ipv4_pool(PoolId=pool_id)

    ctx.on_cleanup(_cleanup)

    # A new pool is briefly not visible to DescribePublicIpv4Pools by PoolIds, which answers
    # InvalidPublicIpv4PoolID.NotFound right after CreatePublicIpv4Pool; bound that wait.
    def _describe():
        try:
            return ec2.describe_public_ipv4_pools(PoolIds=[pool_id])["PublicIpv4Pools"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidPublicIpv4PoolID.NotFound":
                return None
            raise

    listing = _poll_until(_describe, lambda v: v is not None, timeout_s=30, interval_s=2)
    assert len(listing) == 1 and listing[0]["PoolId"] == pool_id, listing

    ec2.delete_public_ipv4_pool(PoolId=pool_id)
    state["deleted"] = True

    # Independent read proves the pool is gone: DescribePublicIpv4Pools with an explicit
    # PoolIds filter raises the specific not-found code for a missing id rather than
    # silently returning an empty list.
    code_after_delete, message_after_delete = _error_of(lambda: ec2.describe_public_ipv4_pools(PoolIds=[pool_id]))
    assert code_after_delete == "InvalidPublicIpv4PoolID.NotFound", f"unexpected code: {code_after_delete}"
    assert message_after_delete == f"The pool ID '{pool_id}' does not exist.", message_after_delete

    # A mutation on the deleted id, and on ids the caller never owned,
    # all fail with the same not-found/invalid-parameter contract -- never a silent
    # no-op success.
    for bogus_pool_id in (pool_id, "ipv4pool-ec2-00000000000000000", "ipv4pool-ec2-0123456789abcdef0"):
        code, message = _error_of(lambda pid=bogus_pool_id: ec2.delete_public_ipv4_pool(PoolId=pid))
        assert (
            "NotFound" in code or code == "InvalidParameterValue"
        ), f"unexpected code for {bogus_pool_id}: {code}"
        if code != "InvalidParameterValue":
            assert message == f"The pool ID '{bogus_pool_id}' does not exist.", message


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not observed within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)


def _error_of(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected DeletePublicIpv4Pool to reject, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
