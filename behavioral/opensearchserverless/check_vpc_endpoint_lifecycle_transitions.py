"""vpc-endpoint-lifecycle-transitions."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vpc-endpoint-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control",
      "resource:account-singleton:aoss-vpc-endpoint")
def run(ctx) -> None:
    """VpcEndpoint reaches ACTIVE, updates in place, then is deleted and gone."""
    ec2 = ctx.client("ec2")
    aoss = ctx.client("opensearchserverless")
    tag_value = ctx.unique_name("sim2real-vpce")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[_tag_spec("vpc", tag_value)],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    # AOSS's managed VPC endpoint always enables private DNS, which EC2 rejects
    # at CreateVpcEndpoint time unless both VPC attributes are already on.
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.91.0.0/24",
        TagSpecifications=[_tag_spec("subnet", tag_value)],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    sg1_id = ec2.create_security_group(
        GroupName=tag_value + "-sg1", Description="sim2real behavioral sg1", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg1_id)))
    sg2_id = ec2.create_security_group(
        GroupName=tag_value + "-sg2", Description="sim2real behavioral sg2", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg2_id)))

    name = _short_name(ctx, "sim2real-vpce")
    created = aoss.create_vpc_endpoint(
        name=name, vpcId=vpc_id, subnetIds=[subnet_id], securityGroupIds=[sg1_id]
    )["createVpcEndpointDetail"]
    endpoint_id = created["id"]
    assert created["status"] == "PENDING", (
        f"expected CreateVpcEndpoint to report PENDING, got {created['status']!r}"
    )

    def _cleanup_endpoint() -> None:
        try:
            aoss.delete_vpc_endpoint(id=endpoint_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_endpoint)

    details = _poll_until(
        lambda: aoss.batch_get_vpc_endpoint(ids=[endpoint_id])["vpcEndpointDetails"],
        lambda d: bool(d) and d[0]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=900,
        interval_s=20,
    )
    assert details[0]["status"] == "ACTIVE", (
        f"vpc endpoint never reached ACTIVE (last={details[0]!r})"
    )
    assert details[0]["subnetIds"] == [subnet_id], (
        f"expected subnetIds == [{subnet_id!r}], got {details[0]['subnetIds']!r}"
    )

    aoss.update_vpc_endpoint(id=endpoint_id, addSecurityGroupIds=[sg2_id])

    updated_details = _poll_until(
        lambda: aoss.batch_get_vpc_endpoint(ids=[endpoint_id])["vpcEndpointDetails"],
        lambda d: bool(d)
        and d[0]["status"] == "ACTIVE"
        and sg2_id in d[0].get("securityGroupIds", []),
        timeout_s=300,
        interval_s=15,
    )
    assert sg1_id in updated_details[0]["securityGroupIds"], (
        f"UpdateVpcEndpoint dropped the original security group {sg1_id!r}: "
        f"{updated_details[0]['securityGroupIds']!r}"
    )
    assert sg2_id in updated_details[0]["securityGroupIds"], (
        f"UpdateVpcEndpoint did not add {sg2_id!r}: {updated_details[0]['securityGroupIds']!r}"
    )

    aoss.delete_vpc_endpoint(id=endpoint_id)

    gone = _poll_until(
        lambda: aoss.batch_get_vpc_endpoint(ids=[endpoint_id]),
        lambda resp: not resp["vpcEndpointDetails"] and bool(resp.get("vpcEndpointErrorDetails")),
        timeout_s=300,
        interval_s=10,
    )
    expected_detail = [
        {
            "id": endpoint_id,
            "errorCode": "NOT_FOUND",
            "errorMessage": "The specified VpcEndpoint is not found.",
        }
    ]
    assert gone["vpcEndpointErrorDetails"] == expected_detail, (
        f"expected {expected_detail!r} reading the deleted endpoint, got {gone!r}"
    )

    # the delete is not just a status flip: a mutation on the now-dead id is itself rejected
    update_code, update_message = _error(
        lambda: aoss.update_vpc_endpoint(id=endpoint_id, addSecurityGroupIds=[sg2_id])
    )
    assert update_code == "ConflictException", (
        f"expected ConflictException updating deleted endpoint {endpoint_id!r}, "
        f"got {update_code!r}"
    )
    # AWS's own wording, grammar included.
    expected = f"The VpcEndpoint with Id '{endpoint_id}' is not exist."
    assert update_message == expected, f"expected message {expected!r}, got {update_message!r}"


# ===== self-contained helpers =====
def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "behavioral"}],
    }


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the AWS error ``fn`` raises; a call that succeeds fails the check."""
    try:
        fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message", "")
    raise AssertionError(f"{fn!r} unexpectedly succeeded")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
