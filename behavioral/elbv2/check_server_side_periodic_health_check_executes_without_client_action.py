"""server-side-periodic-health-check-executes-without-client-action."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-periodic-health-check-executes-without-client-action"
GROUP = "server-side"
SERVICES = ["elbv2"]


# timing:real-time — metric: 60 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A registered Lambda target with health checks enabled is invoked by the load balancer on its own
    schedule: AWS/Lambda Invocations rises while the check makes no DescribeTargetHealth call."""
    elbv2 = ctx.client("elbv2")
    lam = ctx.client("lambda")
    _vpc_id, subnet_ids = _setup_network(ctx)
    role_arn = _create_lambda_role(ctx)
    function_arn = _create_lambda_function(ctx, role_arn)
    function_name = function_arn.split(":")[-1]

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-behav-")[:32],
        TargetType="lambda",
        HealthCheckEnabled=True,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    elbv2.modify_target_group(
        TargetGroupArn=tg_arn, HealthCheckIntervalSeconds=6, HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2,
    )
    lam.add_permission(
        FunctionName=function_arn,
        StatementId="sim2real-elb-invoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_arn,
    )
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": function_arn}])

    lb_arn = _create_alb(ctx, subnet_ids)
    _create_forwarding_listener(ctx, lb_arn, 80, tg_arn)

    # Deliberately issue NO DescribeTargetHealth (or any other poll of the target's
    # health) from here on - the only calls made while waiting are the CloudWatch
    # metric reads below, which observe but cannot influence the load balancer's own
    # health-check schedule. The bounded retry inside _wait_for_metric_sum is the
    # wait; there is no raw sleep standing in for it.
    window_start = datetime.now(timezone.utc)
    invocations = _wait_for_metric_sum(
        ctx, namespace="AWS/Lambda", metric_name="Invocations",
        dimensions=[{"Name": "FunctionName", "Value": function_name}],
        start_time=window_start, timeout_s=_budget_s(ctx, 300.0),
    )
    if invocations is None:
        if _budget_spent(ctx):
            raise TimeoutError("the AWS/Lambda Invocations metric landing: the run budget ended "
                               "first; not graded")
        raise AssertionError(
            "AWS/Lambda Invocations metric never landed within 5 minutes of "
            "ingestion latency; cannot confirm autonomous health checks via telemetry"
        )
    assert invocations >= 1, (
        "expected the load balancer to have autonomously invoked the Lambda target "
        f"at least once with no client polling, got sum={invocations}"
    )

    # DescribeTargetHealth is read only after the metric shows the server-side checks ran, to
    # confirm they drive the target to healthy once HealthyThresholdCount of them have passed.
    state = None
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": function_arn}])
        state = health["TargetHealthDescriptions"][0]["TargetHealth"]["State"]
        if state == "healthy" or time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    if state != "healthy" and _budget_spent(ctx):
        raise TimeoutError(f"target {function_arn} becoming healthy: the run budget ended first; "
                           f"not graded")
    assert state == "healthy", f"expected healthy target after autonomous checks, got {state}"



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _setup_network(ctx, num_subnets: int = 2) -> tuple[str, list[str]]:
    """Adopt the shared network if one exists; otherwise create a scratch VPC and
    subnets of our own. A freshly provisioned account may have no shared network,
    and that must not surface as a bare IndexError."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az: dict[str, str] = {}
        for s in sorted(subnets, key=lambda s: s["SubnetId"]):
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = [by_az[az] for az in sorted(by_az)][:num_subnets]
        if len(subnet_ids) >= min(num_subnets, 2):
            return vpc_id, subnet_ids

    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real", "Value": "behavioral"}])
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    if len(subnet_ids) < 2:
        raise AssertionError("could not provision subnets in at least 2 AZs for this check")
    return vpc_id, subnet_ids


def _create_alb(ctx, subnet_ids: list[str]) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-")[:32]
    lb = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_lb_active(ctx, lb_arn, timeout_s=_budget_s(ctx, 240.0))
    return lb_arn


def _wait_lb_active(ctx, lb_arn: str, timeout_s: float = 240.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        if lb["State"]["Code"] == "active":
            return
        if lb["State"]["Code"] == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State']}")
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"load balancer {lb_arn} becoming active: the run budget ended first; "
                           f"not graded")
    raise AssertionError("load balancer never became active in time")


def _create_forwarding_listener(ctx, lb_arn: str, port: int, tg_arn: str) -> str:
    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-elb-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _lambda_zip_bytes() -> bytes:
    code = (
        "def handler(event, context):\n"
        "    return {'statusCode': 200, 'statusDescription': '200 OK', "
        "'isBase64Encoded': False, 'headers': {'Content-Type': 'text/plain'}, "
        "'body': 'ok'}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    func_name = ctx.unique_name("sim2real-behav-")
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    last_exc: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
            )
            break
        except Exception as exc:  # noqa: BLE001 - retry while the new role propagates
            last_exc = exc
            time.sleep(2.0)
    if resp is None:
        if _budget_spent(ctx):
            raise TimeoutError(f"CreateFunction {func_name} waiting for its role to propagate: "
                               f"the run budget ended first; not graded")
        raise AssertionError(f"lambda create_function never succeeded: {last_exc}")
    function_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=func_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return function_arn


def _wait_for_metric_sum(ctx, namespace, metric_name, dimensions, start_time, timeout_s):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end_time = datetime.now(timezone.utc)
        resp = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, Dimensions=dimensions,
            StartTime=start_time - timedelta(minutes=1), EndTime=end_time + timedelta(minutes=1),
            Period=60, Statistics=["Sum"],
        )
        datapoints = resp.get("Datapoints", [])
        if datapoints:
            return sum(dp["Sum"] for dp in datapoints)
        time.sleep(2.0)
    return None


# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry inside one shared window, then fail naming the ENIs left.
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


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
