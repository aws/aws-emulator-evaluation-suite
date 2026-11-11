"""get-vpc-links-lists-created."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-vpc-links-lists-created"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVpcLinks reflects a newly created vpc link."""
    apigw = ctx.client("apigateway")
    nlb_arn = _create_internal_nlb(ctx)

    name = ctx.unique_name("sim2real-apigw-vpclink-list-")
    created = apigw.create_vpc_link(name=name, targetArns=[nlb_arn])
    vpc_link_id = created["id"]
    ctx.on_cleanup(lambda: _cleanup_vpc_link(apigw, vpc_link_id))

    found = _find_in_paginated(
        lambda position: apigw.get_vpc_links(**({"position": position} if position else {})),
        item_key="items",
        matches=lambda item: item.get("id") == vpc_link_id,
        timeout_s=60,
    )
    assert found is not None, f"vpc link {vpc_link_id} not present in GetVpcLinks"
    assert found["name"] == name, f"expected name {name!r}, got {found['name']!r}"
    assert found["targetArns"] == [nlb_arn], (
        f"expected targetArns {[nlb_arn]!r}, got {found['targetArns']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _find_in_paginated(page_fn, *, item_key, matches, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    position = None
    while True:
        page = page_fn(position)
        for item in page.get(item_key, []):
            if matches(item):
                return item
        position = page.get("position")
        if not position or time.monotonic() >= deadline:
            return None


def _cleanup_vpc_link(apigw, vpc_link_id: str) -> None:
    try:
        state = apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    if state in ("PENDING", "AVAILABLE"):
        _poll_until(
            lambda: _safe_status(apigw, vpc_link_id),
            lambda s: s in ("AVAILABLE", "FAILED", None),
            timeout_s=300, interval_s=10,
        )
    try:
        apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_status(apigw, vpc_link_id: str):
    try:
        return apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return None


def _create_internal_nlb(ctx) -> str:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    tag = ctx.unique_name("sim2real-apigw-nlb-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.224.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.224.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    lb_name = tag[:32].rstrip("-")
    lb = elbv2.create_load_balancer(
        Name=lb_name, Type="network", Scheme="internal", Subnets=[subnet_id],
        Tags=[{"Key": "Name", "Value": tag}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]

    def _cleanup_nlb():
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
        _poll_until(
            lambda: _nlb_exists(elbv2, lb_arn),
            lambda exists: not exists,
            timeout_s=180, interval_s=10,
        )

    ctx.on_cleanup(_cleanup_nlb)

    # Deliberately not waiting for the NLB to be active: CreateVpcLink accepts a still-provisioning
    # target, and the wait would only spend the check's time budget.
    return lb_arn


def _nlb_exists(elbv2, lb_arn: str) -> bool:
    try:
        elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        return False


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
