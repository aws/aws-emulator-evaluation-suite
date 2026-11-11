"""update-vpc-endpoint-concurrent-config-race-conflict."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-vpc-endpoint-concurrent-config-race-conflict"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Two concurrent UpdateVpcEndpoint calls on one endpoint serialize: the loser gets ConflictException
    with one of AWS's two exact in-progress messages, the final config is only the winner's, and a
    follow-up update succeeds once the endpoint is idle again."""
    opensearch = ctx.client("opensearch")
    net = _create_test_network(ctx)

    domain_name, domain_arn = _create_vpc_domain(ctx, "ve", net["subnet_id"], net["sg_ids"][0])
    _wait_domain_active(ctx, domain_name)

    endpoint_id = _create_vpc_endpoint(ctx, domain_arn, net["subnet_id"], net["sg_ids"][0])
    initial_status = _wait_endpoint_status(ctx, endpoint_id, {"ACTIVE", "CREATE_FAILED"})
    assert initial_status == "ACTIVE", f"endpoint did not become ACTIVE after creation (status={initial_status!r})"

    target_a = net["sg_ids"][1]
    target_b = net["sg_ids"][2]

    def _update(sg_id):
        return opensearch.update_vpc_endpoint(
            VpcEndpointId=endpoint_id,
            VpcOptions={"SubnetIds": [net["subnet_id"]], "SecurityGroupIds": [sg_id]},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_update, target_a)
        fut_b = pool.submit(_update, target_b)
        results = {}
        for label, fut in (("a", fut_a), ("b", fut_b)):
            try:
                results[label] = ("ok", fut.result())
            except Exception as exc:  # noqa: BLE001
                code = exc.response["Error"]["Code"] if hasattr(exc, "response") else None
                message = exc.response["Error"].get("Message") if hasattr(exc, "response") else None
                results[label] = ("err", code, message)

    successes = [k for k, v in results.items() if v[0] == "ok"]
    failures = [k for k, v in results.items() if v[0] == "err"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == 1, f"expected exactly 1 loser, got {len(failures)}: {results}"
    assert results[failures[0]][1] == "ConflictException", f"loser got unexpected code {results[failures[0]][1]!r}"
    # AWS names the in-progress operation as either "update" or "delete" for a racing update.
    expected_messages = (
        "A update operation is already in progress for this VPC endpoint.",
        "A delete operation is already in progress for this VPC endpoint.",
    )
    assert results[failures[0]][2] in expected_messages, (
        f"loser's ConflictException message {results[failures[0]][2]!r} is neither of {expected_messages!r}"
    )

    winner_label = successes[0]
    winner_target = target_a if winner_label == "a" else target_b
    loser_target = target_b if winner_label == "a" else target_a

    final_status = _wait_endpoint_status(ctx, endpoint_id, {"ACTIVE", "UPDATE_FAILED"})
    assert final_status == "ACTIVE", f"endpoint did not return to ACTIVE (status={final_status!r})"
    final_sgs = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])[
        "VpcEndpoints"
    ][0]["VpcOptions"]["SecurityGroupIds"]
    assert final_sgs == [winner_target], f"final SecurityGroupIds {final_sgs!r} != winner's {[winner_target]!r}"
    assert loser_target not in final_sgs, "the loser's config leaked into the final endpoint state"

    # Positive control: with the endpoint idle, a follow-up update must succeed --
    # proves the API is not just rejecting UpdateVpcEndpoint outright.
    control_target = net["sg_ids"][0]
    opensearch.update_vpc_endpoint(
        VpcEndpointId=endpoint_id,
        VpcOptions={"SubnetIds": [net["subnet_id"]], "SecurityGroupIds": [control_target]},
    )
    control_status = _wait_endpoint_status(ctx, endpoint_id, {"ACTIVE", "UPDATE_FAILED"})
    assert control_status == "ACTIVE", "control update did not settle to ACTIVE"
    control_sgs = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0][
        "VpcOptions"
    ]["SecurityGroupIds"]
    assert control_sgs == [control_target], f"control update did not apply: {control_sgs!r}"


# ===== self-contained helpers =====

def _short_name(ctx, tag: str, maxlen: int) -> str:
    raw = ctx.unique_name(f"os{tag}").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    if len(raw) > maxlen:
        keep_tail = maxlen - 6
        raw = raw[:6] + raw[-keep_tail:]
    if not raw or not raw[0].isalpha():
        raw = "a" + raw[1:]
    return raw[:maxlen]


def _tag_spec(resource_type: str, name: str):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _create_test_network(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-osve-")
    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16", TagSpecifications=_tag_spec("vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_ec2(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.91.1.0/24", TagSpecifications=_tag_spec("subnet", name)
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe_ec2(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
    ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sg_ids = []
    for i in range(3):
        sg_name = f"{name}sg{i}"
        sg_id = ec2.create_security_group(
            GroupName=sg_name, Description="sim2real behavioral test sg", VpcId=vpc_id,
            TagSpecifications=_tag_spec("security-group", sg_name),
        )["GroupId"]
        ctx.on_cleanup(lambda sg_id=sg_id: _safe_ec2(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))
        sg_ids.append(sg_id)

    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_ids": sg_ids}


# The not-found codes of the teardown deletes below: an already-absent resource is the only
# outcome a teardown tolerates.
_GONE_CODES = {"InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
               "ResourceNotFoundException"}


def _safe_ec2(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
            raise


def _create_vpc_domain(ctx, tag: str, subnet_id: str, sg_id: str):
    opensearch = ctx.client("opensearch")
    name = _short_name(ctx, tag, 28)
    resp = opensearch.create_domain(
        DomainName=name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name, resp["DomainStatus"]["ARN"]


def _safe_delete_domain(ctx, name: str) -> None:
    try:
        ctx.client("opensearch").delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_domain_active(ctx, name: str, timeout_s: float = 2700, interval_s: float = 2):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return status
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {name} becoming active: the run budget ended first; not graded")
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s")


def _create_vpc_endpoint(ctx, domain_arn: str, subnet_id: str, sg_id: str, timeout_s: float = 300, interval_s: float = 2) -> str:
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = opensearch.create_vpc_endpoint(
                DomainArn=domain_arn, VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]}
            )
            break
        except Exception as exc:  # noqa: BLE001
            # Real AWS: DomainStatus can report Created=True/Processing=False slightly before the
            # domain is actually ready to accept a VPC endpoint -- CreateVpcEndpoint answers
            # ValidationException("...currently being created") for a bounded window after that.
            code = exc.response["Error"]["Code"] if hasattr(exc, "response") else None
            message = exc.response["Error"].get("Message", "") if hasattr(exc, "response") else ""
            if code == "ValidationException" and "currently being created" in message:
                if time.monotonic() < deadline:
                    time.sleep(interval_s)
                    continue
                if _budget_spent(ctx):
                    raise TimeoutError(f"CreateVpcEndpoint on {domain_arn}: the run budget ended first; not graded") from exc
            raise
    endpoint_id = resp["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint(opensearch, endpoint_id))
    return endpoint_id


def _delete_vpc_endpoint(opensearch, endpoint_id: str, timeout_s: float = 300) -> None:
    """DeleteVpcEndpoint, retrying ConflictException (an update still in progress) for up to 300 s."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            opensearch.delete_vpc_endpoint(VpcEndpointId=endpoint_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_endpoint_status(ctx, endpoint_id: str, terminal: set, timeout_s: float = 900, interval_s: float = 2):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = opensearch.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]["Status"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"vpc endpoint {endpoint_id} reaching {terminal}: the run budget ended first; not graded")
    raise AssertionError(f"vpc endpoint {endpoint_id} did not reach {terminal} within {timeout_s}s (last status={status!r})")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes and fits the suite's cleanup budget.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
