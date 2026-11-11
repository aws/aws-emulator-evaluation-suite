"""op-contract-modify-vpc-block-public-access-exclusion."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-block-public-access-exclusion"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcBlockPublicAccessExclusion: success updates the exclusion mode and
    surfaces the state-machine transition; DryRun is rejected with DryRunOperation."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.201.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "bpa-vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.201.1.0/24", TagSpecifications=_tag_spec(ctx, "subnet", "bpa-subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    created = ec2.create_vpc_block_public_access_exclusion(
        SubnetId=subnet_id,
        InternetGatewayExclusionMode="allow-egress",
        TagSpecifications=_tag_spec(ctx, "vpc-block-public-access-exclusion", "bpa-excl"),
    )["VpcBlockPublicAccessExclusion"]
    exclusion_id = created["ExclusionId"]

    def _cleanup_exclusion():
        from botocore.exceptions import ClientError

        try:
            ec2.delete_vpc_block_public_access_exclusion(ExclusionId=exclusion_id)
            # Real AWS holds an exclusion in delete-in-progress for minutes; the wait stays inside
            # budget.cleanup_timeout for behavioral/ec2 (900 s).
            _poll_until(
                lambda: _describe_exclusion(ec2, exclusion_id),
                lambda excl: excl is None or excl.get("State", "").startswith("delete-complete"),
                timeout_s=600,
                interval_s=2,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcBlockPublicAccessExclusionId.NotFound":
                raise

    ctx.on_cleanup(_cleanup_exclusion)

    created_state = _poll_until(
        lambda: _describe_exclusion(ec2, exclusion_id),
        lambda excl: excl is not None and excl.get("State") in ("create-complete", "create-failed"),
        timeout_s=300,
        interval_s=10,
    )
    assert created_state is not None and created_state["State"] == "create-complete", created_state
    assert created_state["InternetGatewayExclusionMode"] == "allow-egress", created_state

    # error boundary: DryRun must reject without mutating state.
    err, err_message = _client_error(
        lambda: ec2.modify_vpc_block_public_access_exclusion(
            ExclusionId=exclusion_id, InternetGatewayExclusionMode="allow-bidirectional", DryRun=True
        )
    )
    assert err == "DryRunOperation", err
    expected_message = "Request would have succeeded, but DryRun flag is set."
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"

    # effect-absent: the DryRun must not have mutated anything -- an independent read still
    # shows the pre-DryRun mode and state, not a transition toward allow-bidirectional.
    unmutated = _describe_exclusion(ec2, exclusion_id)
    assert unmutated is not None and unmutated["State"] == "create-complete", unmutated
    assert unmutated["InternetGatewayExclusionMode"] == "allow-egress", unmutated

    # success path: mutate and observe the update-complete transition.
    ec2.modify_vpc_block_public_access_exclusion(
        ExclusionId=exclusion_id, InternetGatewayExclusionMode="allow-bidirectional"
    )
    updated_state = _poll_until(
        lambda: _describe_exclusion(ec2, exclusion_id),
        lambda excl: excl is not None and excl.get("State") in ("update-complete", "update-failed"),
        timeout_s=300,
        interval_s=10,
    )
    assert updated_state is not None and updated_state["State"] == "update-complete", updated_state
    assert updated_state["InternetGatewayExclusionMode"] == "allow-bidirectional", updated_state


# ===== helpers =====
def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed {last!r}")


def _describe_exclusion(ec2, exclusion_id):
    resp = ec2.describe_vpc_block_public_access_exclusions(ExclusionIds=[exclusion_id])
    items = resp.get("VpcBlockPublicAccessExclusions", [])
    return items[0] if items else None


# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside one window shared by the
# check's network deletes and the suite's cleanup budget, then raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
