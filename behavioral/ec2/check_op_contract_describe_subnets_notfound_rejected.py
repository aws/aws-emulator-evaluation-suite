"""op-contract-describe-subnets-notfound-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-subnets-notfound-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSubnets by the run network's subnet IDs returns exactly those subnets, and an unknown
    SubnetId fails with InvalidSubnetID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    net = ctx.network()
    want = sorted((sid, net.vpc_id) for sid in net.subnet_ids)
    # DescribeSubnets is eventually consistent for a just-created network: it may still answer
    # InvalidSubnetID.NotFound for the run's own subnets, so poll, bounded. The ids are named
    # directly, since a MaxResults page is cut before a subnet-id filter applies.
    deadline = time.monotonic() + max(1.0, min(30.0, (ctx.time_left() or 30.0) - 10.0))
    while True:
        try:
            resp = ec2.describe_subnets(SubnetIds=net.subnet_ids)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        assert "Subnets" in resp, f"expected a 'Subnets' key, got keys {sorted(resp)!r}"
        got = sorted((s["SubnetId"], s["VpcId"]) for s in resp["Subnets"])
        if got == want or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert got == want, f"DescribeSubnets(SubnetIds) returned {got!r}, expected exactly {want!r}"

    fake_subnet = "subnet-ffffffffffffffff"
    code, message = _error(lambda: ec2.describe_subnets(SubnetIds=[fake_subnet]))
    assert code == "InvalidSubnetID.NotFound", f"expected NotFound, got {code!r}"
    assert message == f"The subnet ID '{fake_subnet}' does not exist", message


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
