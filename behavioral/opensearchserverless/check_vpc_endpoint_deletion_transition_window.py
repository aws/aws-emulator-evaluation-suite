"""vpc-endpoint-deletion-transition-window."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vpc-endpoint-deletion-transition-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control",
      "resource:account-singleton:aoss-vpc-endpoint")
def run(ctx) -> None:
    """A deleted VpcEndpoint transitions through DELETING before BatchGetVpcEndpoint reports it
    gone, NOT_FOUND with AWS's exact message."""
    client = ctx.client("opensearchserverless")
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx)

    name = ctx.unique_name("sim2real-vpce-")
    detail = client.create_vpc_endpoint(name=name, vpcId=vpc_id, subnetIds=[subnet_id])[
        "createVpcEndpointDetail"
    ]
    endpoint_id = detail["id"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(ctx, endpoint_id))

    status = _poll_until(
        lambda: _endpoint_status(client, endpoint_id),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    assert status == "ACTIVE", f"vpc endpoint never reached ACTIVE (last status {status!r})"

    del_detail = client.delete_vpc_endpoint(id=endpoint_id)["deleteVpcEndpointDetail"]
    assert del_detail["id"] == endpoint_id, (
        f"DeleteVpcEndpoint should echo {endpoint_id!r}, got {del_detail['id']!r}"
    )
    assert del_detail["status"] == "DELETING", (
        f"DeleteVpcEndpoint should report DELETING, got {del_detail['status']!r}"
    )

    immediate = client.batch_get_vpc_endpoint(ids=[endpoint_id]).get("vpcEndpointDetails", [])
    assert len(immediate) == 1, (
        f"vpc endpoint should still be visible immediately after DeleteVpcEndpoint, got {immediate}"
    )
    assert immediate[0]["status"] == "DELETING", (
        f"vpc endpoint should still report DELETING immediately after delete, got {immediate[0]['status']!r}"
    )

    final = _poll_until(
        lambda: client.batch_get_vpc_endpoint(ids=[endpoint_id]),
        lambda r: not r.get("vpcEndpointDetails", []),
        timeout_s=1200,
        interval_s=20,
    )
    assert not final.get("vpcEndpointDetails", []), (
        f"vpc endpoint is still present in BatchGetVpcEndpoint after the purge window: {final}"
    )
    errors = final.get("vpcEndpointErrorDetails", [])
    assert len(errors) == 1 and errors[0].get("id") == endpoint_id, (
        f"expected exactly one error detail for {endpoint_id!r} after purge, got {errors}"
    )
    assert errors[0]["errorCode"] == "NOT_FOUND", (
        f"expected NOT_FOUND for the purged endpoint, got {errors[0]}"
    )
    assert errors[0]["errorMessage"] == "The specified VpcEndpoint is not found.", (
        f"expected the exact NOT_FOUND message for the purged endpoint, got {errors[0]}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _endpoint_status(client, endpoint_id):
    resp = client.batch_get_vpc_endpoint(ids=[endpoint_id])
    details = resp.get("vpcEndpointDetails", [])
    return details[0]["status"] if details else "GONE"


def _safe_delete_endpoint(ctx, endpoint_id, timeout_s=1200.0, interval_s=20.0):
    client = ctx.client("opensearchserverless")
    status = _poll_until(
        lambda: _endpoint_status(client, endpoint_id),
        lambda s: s in ("ACTIVE", "FAILED", "GONE"),
        timeout_s,
        interval_s,
    )
    if status == "GONE":
        return
    try:
        client.delete_vpc_endpoint(id=endpoint_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    tag_name = ctx.unique_name("sim2real-aoss-vpce-")

    vpc = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    # CreateVpcEndpoint enables private DNS, which AWS rejects unless the VPC has both
    # DNS attributes on; create_vpc leaves enableDnsHostnames off by default.
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.0.0/24",
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag_name}]}
        ],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    return vpc_id, subnet_id


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that would leak the
# VPC. So wait (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same
# window, and raise a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's 900s cleanup budget.
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
