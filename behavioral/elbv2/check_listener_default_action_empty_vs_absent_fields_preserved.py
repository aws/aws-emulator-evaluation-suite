"""listener-default-action-empty-vs-absent-fields-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "listener-default-action-empty-vs-absent-fields-preserved"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRules mirrors a path-pattern PathPatternConfig into top-level Values, while an
    http-header condition has no Values key at all rather than an empty list.
    """
    vpc_id, subnet_ids, sg_id = _provision_alb_network(ctx)
    _lb, lb_arn = _create_alb(ctx, subnet_ids, sg_id)
    tg_arn = _create_target_group(ctx, vpc_id)

    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    # Registered after the target group's cleanup, so it runs first: the listener and its rules
    # hold the target group, and DeleteTargetGroup refuses while they exist.
    ctx.on_cleanup(lambda: _delete_listener(elbv2, listener_arn))

    rule_path = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/only-config"]}}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Rules"][0]

    rule_header = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=20,
        Conditions=[
            {
                "Field": "http-header",
                "HttpHeaderConfig": {"HttpHeaderName": "X-Sim2Real-Test", "Values": ["probe"]},
            }
        ],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Rules"][0]

    described = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    by_arn = {r["RuleArn"]: r for r in described}

    path_cond = by_arn[rule_path["RuleArn"]]["Conditions"][0]
    header_cond = by_arn[rule_header["RuleArn"]]["Conditions"][0]

    assert path_cond.get("Values") == ["/only-config"], (
        f"expected path-pattern Values mirrored from PathPatternConfig, got {path_cond.get('Values')!r}"
    )
    assert "Values" not in header_cond, (
        f"http-header condition must have no legacy Values key at all, got {header_cond!r}"
    )


# ===== helpers =====

def _provision_alb_network(ctx):
    """Create a minimal VPC + 2 subnets (different AZs) + default SG, sufficient for an internal ALB."""
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.178.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
    )

    def _delete_vpc():
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_delete_vpc)

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs if az["State"] == "available"][:2]
    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.178.{i}.0/24", AvailabilityZone=az)["Subnet"]
        sid = subnet["SubnetId"]
        subnet_ids.append(sid)

        def _delete_subnet(sid=sid):
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise

        ctx.on_cleanup(_delete_subnet)

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _create_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-lb-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]

    def _delete_lb():
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
            except elbv2.exceptions.LoadBalancerNotFoundException:
                return
            time.sleep(2)

    ctx.on_cleanup(_delete_lb)
    return lb, lb_arn


def _create_target_group(ctx, vpc_id):
    elbv2 = ctx.client("elbv2")
    tg = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-behav-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group(elbv2, tg_arn))
    return tg_arn


def _delete_listener(elbv2, listener_arn):
    try:
        elbv2.delete_listener(ListenerArn=listener_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ListenerNotFound":
            raise


def _delete_target_group(elbv2, tg_arn, timeout_s=120):
    """Retry on ResourceInUse, which outlasts the listener's delete briefly; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=tg_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


# Resources in this VPC (load balancers, endpoints, functions, ...) delete asynchronously and
# leave ENIs behind, so network deletes answer DependencyViolation for a while. Wait, bounded,
# for those ENIs to go, then raise naming any still attached. The window is shared by all of a
# check's network deletes.
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
