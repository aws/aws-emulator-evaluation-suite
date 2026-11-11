"""delete-vpc-link-in-use-by-integration-conflict."""
from __future__ import annotations

import time

CHECK = "delete-vpc-link-in-use-by-integration-conflict"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVpcLink is rejected with BadRequestException while an Integration still
    references it via connectionType=VPC_LINK, rather than silently orphaning the
    integration; removing the integration first lets the identical delete succeed."""
    apigw = ctx.client("apigateway")

    vpc_id, subnet_id = _create_vpc_and_subnet(ctx)
    lb_arn = _create_network_load_balancer(ctx, subnet_id, vpc_id)

    vpc_link_id = apigw.create_vpc_link(name=ctx.unique_name("sim2real-vpclink-"), targetArns=[lb_arn])[
        "id"
    ]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id), "NotFoundException"))

    # VpcLink provisioning reads "being configured" well past 150s after its NLB is active.
    link = _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=600.0,
        interval_s=5.0,
    )
    if link["status"] != "AVAILABLE":
        raise AssertionError(
            f"VpcLink never reached AVAILABLE: {link.get('statusMessage')}"
        )

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: apigw.delete_rest_api(restApiId=api_id), "NotFoundException"))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP_PROXY",
        integrationHttpMethod="GET",
        uri="http://internal.example.com/",
        connectionType="VPC_LINK",
        connectionId=vpc_link_id,
    )

    code, message = _client_error(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id))
    assert code == "BadRequestException", (
        f"expected BadRequestException deleting a VpcLink with an active Integration "
        f"reference, got {code!r}"
    )
    assert message == (
        f"Cannot delete vpc link. Vpc link '{vpc_link_id}', is referenced in "
        f"[{api_id}:GET:{root_id}] in format of [RESTApiId:Method:Resource]."
    ), message

    # The rejected delete must not have mutated the VpcLink.
    still_there = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert still_there["id"] == vpc_link_id

    # Positive control: remove the referencing integration, then delete succeeds.
    apigw.delete_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    apigw.delete_vpc_link(vpcLinkId=vpc_link_id)

    final_code, final_message = _wait_gone(apigw, vpc_link_id, timeout_s=60.0, interval_s=5.0)
    assert final_code == "NotFoundException", final_code
    assert final_message == "Invalid Vpc Link identifier specified", final_message


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _wait_gone(apigw, vpc_link_id, *, timeout_s, interval_s):
    """Poll GetVpcLink until it fails; return that (code, message), or raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.get_vpc_link(vpcLinkId=vpc_link_id)
        except ClientError as err:
            error = err.response["Error"]
            return error["Code"], error.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError("VpcLink deletion did not complete within the polling budget")
        time.sleep(interval_s)


def _ignore_missing(fn, *missing):
    """Teardown: run one delete, tolerating only the resource's not-found codes; throttling is
    retried for 60 s, and anything else raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in missing:
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _create_vpc_and_subnet(ctx) -> tuple[str, str]:
    """Any VPC/subnet for the NLB: reuse an available one to spare the low VPC quota, else create one."""
    ec2 = ctx.client("ec2")

    from botocore.exceptions import ClientError

    existing_vpcs = ec2.describe_vpcs(Filters=[{"Name": "state", "Values": ["available"]}])["Vpcs"]
    for vpc in existing_vpcs:
        vpc_id = vpc["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]

    def _tag_spec(resource_type: str, name: str):
        return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]

    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.211.0.0/16",
            TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-vpc-")),
        )["Vpc"]["VpcId"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "VpcLimitExceeded":
            raise AssertionError(
                "no existing usable VPC/subnet found and the account VPC quota is exhausted"
            )
        raise
    ctx.on_cleanup(lambda: _ignore_missing(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound"))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=_tag_spec("subnet", ctx.unique_name("sim2real-subnet-")),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id), "InvalidSubnetID.NotFound"
    ))
    return vpc_id, subnet_id


def _create_network_load_balancer(ctx, subnet_id: str, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    lb_name = ctx.unique_name("sim2real-nlb-")[:32].rstrip("-")
    resp = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=[subnet_id],
        Type="network",
        Scheme="internal",
        Tags=[{"Key": "Name", "Value": lb_name}],
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]

    def _cleanup_lb():
        _ignore_missing(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn), "LoadBalancerNotFound")
        elbv2.get_waiter("load_balancers_deleted").wait(LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup_lb)

    # Real AWS marks a VPC Link's target NLB as unusable (VpcLink status FAILED) unless the
    # NLB has at least one listener; attach a minimal TCP listener backed by a target group
    # (targets need not be healthy for the VpcLink itself to reach AVAILABLE).
    target_group_arn = elbv2.create_target_group(
        Name=(lb_name[:29].rstrip("-") + "-tg"),
        Protocol="TCP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(
        lambda: _ignore_missing(
            lambda: elbv2.delete_target_group(TargetGroupArn=target_group_arn), "TargetGroupNotFound"
        )
    )

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="TCP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: elbv2.delete_listener(ListenerArn=listener_arn), "ListenerNotFound"
    ))

    # The NLB is still "provisioning" past 90s on real AWS.
    state = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0][
            "State"
        ]["Code"],
        lambda s: s in {"active", "failed"},
        timeout_s=240.0,
        interval_s=5.0,
    )
    if state != "active":
        raise AssertionError(
            f"NLB did not become active within the bounded wait (state={state!r})"
        )
    return lb_arn


# AWS-managed ENIs (endpoints, load balancers, functions) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
