"""update-vpc-link-patch-name."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-vpc-link-patch-name"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateVpcLink patches name/description without affecting targetArns."""
    apigw = ctx.client("apigateway")
    # Wait for the NLB to be active first: AWS fails a VPC link whose target is still
    # provisioning (status FAILED, "NLB is not in active state").
    nlb_arn = _create_network_load_balancer(ctx)

    created = apigw.create_vpc_link(
        name=ctx.unique_name("sim2real-bh-vpclink-"),
        description="original description",
        targetArns=[nlb_arn],
    )
    vpc_link_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id))
    assert created["targetArns"] == [nlb_arn]

    status = _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=600,
        interval_s=15,
    )
    if status["status"] == "FAILED":
        raise AssertionError(f"VPC link provisioning FAILED: {status.get('statusMessage')}")
    if status["status"] != "AVAILABLE":
        raise AssertionError(f"vpc link did not reach AVAILABLE: status={status['status']} msg={status.get('statusMessage')}")

    updated = apigw.update_vpc_link(
        vpcLinkId=vpc_link_id,
        patchOperations=[
            {"op": "replace", "path": "/name", "value": "renamed-vpc-link"},
            {"op": "replace", "path": "/description", "value": "updated description"},
        ],
    )
    assert updated["name"] == "renamed-vpc-link"
    assert updated["description"] == "updated description"
    assert updated["targetArns"] == [nlb_arn], "UpdateVpcLink must not affect targetArns"

    fetched = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert fetched["name"] == "renamed-vpc-link"
    assert fetched["targetArns"] == [nlb_arn]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _create_network_load_balancer(ctx) -> str:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    vpc = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-bh-vpc-")}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.77.0.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-bh-subnet-")}]}],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    nlb_name = ctx.unique_name("sim2real-bh-nlb-")[:32].rstrip("-")
    lb = elbv2.create_load_balancer(
        Name=nlb_name, Type="network", Subnets=[subnet_id], Scheme="internal",
        Tags=[{"Key": "Name", "Value": nlb_name}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]

    def _cleanup_nlb():
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(5)

    ctx.on_cleanup(_cleanup_nlb)

    nlb_state = lb["State"]["Code"]
    deadline = time.monotonic() + 300
    while nlb_state != "active" and time.monotonic() < deadline:
        time.sleep(2)
        nlb_state = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"]
    if nlb_state != "active":
        raise AssertionError(f"NLB never reached active within 300s (last state={nlb_state})")

    return lb_arn


# Resources in a VPC delete asynchronously and leave AWS-managed ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for those ENIs, retries DependencyViolation, then raises naming any still attached.
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
