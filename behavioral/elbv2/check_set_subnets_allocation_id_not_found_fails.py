"""set-subnets-allocation-id-not-found-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-subnets-allocation-id-not-found-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetSubnets on an internet-facing NLB with an unknown EIP allocation id fails with
    AllocationIdNotFound and leaves the EIP mapping unchanged; re-asserting the real ids succeeds."""
    subnets = _get_default_subnets(ctx, count=2)
    allocation_ids = _allocate_eips(ctx, count=2)
    good_mappings = [
        {"SubnetId": sid, "AllocationId": aid}
        for sid, aid in zip(subnets["subnet_ids"], allocation_ids)
    ]
    arn = _create_lb(ctx, good_mappings, scheme="internet-facing", lb_type="network")
    _wait_lb_active(ctx, arn)

    elbv2 = ctx.client("elbv2")

    elbv2.set_subnets(LoadBalancerArn=arn, SubnetMappings=good_mappings)
    original = _poll_allocation_ids(ctx, arn, expected=set(allocation_ids))

    # Only the first mapping carries the unknown id; repeating one id across both subnets is
    # refused for the reuse (ValidationError) before the id is ever looked up.
    fake_allocation_id = "eipalloc-0123456789abcdef0"
    bad_mappings = [{"SubnetId": subnets["subnet_ids"][0], "AllocationId": fake_allocation_id}] + good_mappings[1:]
    code, message = _error(
        lambda: elbv2.set_subnets(LoadBalancerArn=arn, SubnetMappings=bad_mappings)
    )
    assert code == "AllocationIdNotFound", (
        f"expected the unknown allocation id to be rejected with AllocationIdNotFound, got {code!r}"
    )
    # AWS appends the per-request id of its internal EC2 lookup, so the text around it is exact.
    assert message.startswith(
        f"The allocation ID '{fake_allocation_id}' does not exist (Service: AmazonEC2; "
        "Status Code: 400; Error Code: InvalidAllocationID.NotFound; Request ID: "
    ) and message.endswith("; Proxy: null)"), message

    current = _read_allocation_ids(ctx, arn)
    assert current == original, (
        f"EIP mapping changed to {current} despite the rejected SetSubnets call "
        f"(expected it to remain {original})"
    )


# ===== helpers =====
def _error(fn):
    """Call fn() and return its error (code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _get_default_subnets(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = sorted(by_az.values())
    if len(ids) < count:
        raise AssertionError("not enough distinct-AZ subnets in shared network for this check")
    return {"vpc_id": vpc_id, "subnet_ids": ids[:count]}


def _safe_delete_lb(ctx, arn):
    elbv2 = ctx.client("elbv2")
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _create_lb(ctx, subnet_mappings, scheme="internal", lb_type="application"):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name,
        SubnetMappings=subnet_mappings,
        Scheme=scheme,
        Type=lb_type,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-elbv2"},
        ],
    )
    arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_delete_lb(ctx, arn))
    return arn


def _wait_lb_active(ctx, arn, timeout_s=180.0, interval_s=5.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        desc = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
        state = desc["State"]["Code"]
        if state in ("active", "active_impaired", "failed"):
            return state
        time.sleep(interval_s)
    return state


def _allocate_eips(ctx, count):
    ec2 = ctx.client("ec2")
    allocation_ids = []
    for _ in range(count):
        resp = ec2.allocate_address(
            Domain="vpc",
            TagSpecifications=[{
                "ResourceType": "elastic-ip",
                "Tags": [
                    {"Key": "sim2real:managed", "Value": "true"},
                    {"Key": "sim2real:prefix", "Value": "sim2real-elbv2"},
                ],
            }],
        )
        allocation_id = resp["AllocationId"]
        allocation_ids.append(allocation_id)
        ctx.on_cleanup(lambda aid=allocation_id: _safe_release_eip(ctx, aid))
    return allocation_ids


def _safe_release_eip(ctx, allocation_id):
    # The load balancer is deleted first (LIFO cleanup), but its network interfaces hold the
    # address for a while: retry only the in-use refusal, bounded, and raise everything else.
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + 300.0
    while True:
        try:
            ec2.release_address(AllocationId=allocation_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "InvalidAllocationID.NotFound":
                return
            if code not in ("InvalidIPAddress.InUse", "AuthFailure") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _read_allocation_ids(ctx, arn):
    elbv2 = ctx.client("elbv2")
    desc = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    return {
        addr["AllocationId"]
        for az in desc["AvailabilityZones"]
        for addr in az.get("LoadBalancerAddresses", [])
        if "AllocationId" in addr
    }


def _poll_allocation_ids(ctx, arn, expected, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    current = set()
    while time.monotonic() < deadline:
        current = _read_allocation_ids(ctx, arn)
        if current == expected:
            return current
        time.sleep(interval_s)
    raise AssertionError(
        f"load balancer EIP mapping never converged to {expected} within {timeout_s}s "
        f"(last observed {current})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
