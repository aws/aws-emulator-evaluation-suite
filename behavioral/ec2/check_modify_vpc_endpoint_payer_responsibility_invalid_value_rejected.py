"""modify-vpc-endpoint-payer-responsibility-invalid-value-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-vpc-endpoint-payer-responsibility-invalid-value-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcEndpointPayerResponsibility rejects a PayerResponsibility value outside
    the {vpc-endpoint-account, vpc-endpoint-service-account} enum, while a valid value
    is applied and reflected in the endpoint's payer responsibility settings.
    """
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    vpc_id = _create_vpc_with_retry(
        ec2, CidrBlock="10.216.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "payer-vpc")
    )
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    nlb_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.216.1.0/24",
        TagSpecifications=_tag_spec(ctx, "subnet", "payer-nlb-subnet"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet_retrying(ctx, nlb_subnet_id))
    ep_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.216.2.0/24",
        TagSpecifications=_tag_spec(ctx, "subnet", "payer-ep-subnet"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet_retrying(ctx, ep_subnet_id))
    default_sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]

    lb_name = ctx.unique_name("sim2real-behav-nlb-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=[nlb_subnet_id],
        Scheme="internal",
        Type="network",
        IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": lb_name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(
        lambda: _delete_load_balancer_and_wait(ctx, lb_arn, nlb_subnet_id, vpc_id)
    )
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])[
            "LoadBalancers"
        ][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=300,
        interval_s=10,
    )

    service_id = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[lb_arn],
        AcceptanceRequired=False,
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint-service", "payer-svc"),
    )["ServiceConfiguration"]["ServiceId"]
    ctx.on_cleanup(
        lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id])
    )
    service_name = ec2.describe_vpc_endpoint_service_configurations(
        ServiceIds=[service_id]
    )["ServiceConfigurations"][0]["ServiceName"]

    endpoint_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=vpc_id,
        ServiceName=service_name,
        SubnetIds=[ep_subnet_id],
        SecurityGroupIds=[default_sg_id],
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint", "payer-ep"),
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(
        lambda: _delete_vpc_endpoint_and_wait(ctx, endpoint_id)
    )
    _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][
            0
        ]["State"],
        lambda state: state == "available",
        timeout_s=180,
        interval_s=5,
    )

    # Negative: not a member of the PayerResponsibilityType enum.
    code, message = _error(
        lambda: ec2.modify_vpc_endpoint_payer_responsibility(
            ServiceId=service_id,
            VpcEndpointId=endpoint_id,
            PayerResponsibility="requester-pays",
            Scope="vpc-endpoint-charges",
        )
    )
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}"
    assert message == (
        "Invalid payer responsibility. Valid values are: vpc-endpoint-account, vpc-endpoint-service-account"
    ), message

    # Positive control: a valid enum value is applied.
    result = ec2.modify_vpc_endpoint_payer_responsibility(
        ServiceId=service_id,
        VpcEndpointId=endpoint_id,
        PayerResponsibility="vpc-endpoint-service-account",
        Scope="vpc-endpoint-charges",
    )
    entries = result["PayerResponsibilities"]
    assert any(
        e.get("Scope") == "vpc-endpoint-charges"
        and e.get("PayerResponsibilityType") == "vpc-endpoint-service-account"
        for e in entries
    ), result

    # Terminal read: independent of the mutating call, via DescribeVpcEndpoints.
    described = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    described_entries = described.get("PayerResponsibilities", [])
    assert any(
        e.get("Scope") == "vpc-endpoint-charges"
        and e.get("PayerResponsibilityType") == "vpc-endpoint-service-account"
        for e in described_entries
    ), described


# ===== helpers =====
def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _create_vpc_with_retry(ec2, timeout_s=900.0, interval_s=20.0, **kwargs):
    # The account's VPC limit is shared across every check in this suite (several
    # of which each provision their own throwaway VPC), so it is routinely
    # exhausted transiently by sibling checks running concurrently that haven't
    # finished tearing down their own VPCs yet. Widen the retry window enough to
    # realistically outlast a sibling's full lifecycle rather than just a brief blip.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)["Vpc"]["VpcId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "VpcLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_vpc_endpoint_and_wait(ctx, endpoint_id) -> None:
    ec2 = ctx.client("ec2")
    ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id])

    def _state():
        resp = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
        return resp[0]["State"] if resp else "deleted"

    _poll_until(_state, lambda s: s == "deleted", timeout_s=180, interval_s=5)


def _delete_load_balancer_and_wait(ctx, lb_arn, subnet_id, vpc_id) -> None:
    elbv2 = ctx.client("elbv2")
    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)

    def _gone():
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
            return False
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return True

    _poll_until(_gone, lambda g: g, timeout_s=180, interval_s=5)


def _delete_subnet_retrying(ctx, subnet_id) -> None:
    """The NLB's ENIs can take a little longer than the load balancer's own
    deletion to fully detach; retry subnet deletion until that dependency clears.
    """
    ec2 = ctx.client("ec2")

    def _try_delete():
        try:
            _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
                raise
            return False

    _poll_until(_try_delete, lambda ok: ok, timeout_s=120, interval_s=5)


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
