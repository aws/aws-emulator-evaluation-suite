"""target-health-check-state-transition-unhealthy-to-healthy."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "target-health-check-state-transition-unhealthy-to-healthy"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Lambda target whose code returns HTTP 500 is reported unhealthy by DescribeTargetHealth,
    then healthy once the code is updated to return 200."""
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids = _get_default_vpc_subnets(ctx)
    role_arn = _create_lambda_role(ctx)
    function_arn = _create_lambda_function(ctx, role_arn)

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-behav-")[:32],
        TargetType="lambda",
        HealthCheckEnabled=True,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    elbv2.modify_target_group(
        TargetGroupArn=tg_arn,
        HealthCheckIntervalSeconds=10,
        HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
    )

    # RegisterTargets fails with AccessDenied without the ELB invoke permission, so it is granted
    # up front and cannot be what drives the unhealthy state.
    lambda_client = ctx.client("lambda")
    lambda_client.add_permission(
        FunctionName=function_arn,
        StatementId="sim2real-elb-invoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_arn,
    )
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": function_arn}])

    lb_arn = _create_alb(ctx, subnet_ids)
    _create_forwarding_listener(ctx, lb_arn, 80, tg_arn)

    # The function's own code returns a 500: health checks must fail.
    state1 = _wait_for_target_health(ctx, tg_arn, function_arn, lambda s: s != "initial", timeout_s=120.0)
    assert state1 == "unhealthy", f"expected unhealthy before the code fix, got {state1}"

    _update_lambda_to_healthy_response(ctx, function_arn)

    state2 = _wait_for_target_health(ctx, tg_arn, function_arn, lambda s: s == "healthy", timeout_s=120.0)
    assert state2 == "healthy", f"expected healthy after the code fix, got {state2}"


def _get_default_vpc_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an ALB for this check")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 AZs")
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
    _wait_lb_active(ctx, lb_arn)
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
        time.sleep(5)
    raise AssertionError("load balancer never became active in time")


def _create_forwarding_listener(ctx, lb_arn: str, port: int, tg_arn: str) -> str:
    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _lambda_zip_bytes(*, healthy: bool) -> bytes:
    status_code = 200 if healthy else 500
    status_description = "200 OK" if healthy else "500 Internal Server Error"
    body = "ok" if healthy else "bad"
    code = (
        "def handler(event, context):\n"
        f"    return {{'statusCode': {status_code}, 'statusDescription': {status_description!r}, "
        "'isBase64Encoded': False, 'headers': {'Content-Type': 'text/plain'}, "
        f"'body': {body!r}}}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    func_name = ctx.unique_name("sim2real-behav-")
    deadline = time.monotonic() + 60.0
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
                Code={"ZipFile": _lambda_zip_bytes(healthy=False)},
                Timeout=10,
                Tags={"sim2real": "behavioral"},
            )
            break
        except Exception as exc:  # noqa: BLE001 - retry while the new role propagates
            last_exc = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_exc}")
    function_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=func_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return function_arn


def _update_lambda_to_healthy_response(ctx, function_arn: str) -> None:
    lam = ctx.client("lambda")
    lam.update_function_code(FunctionName=function_arn, ZipFile=_lambda_zip_bytes(healthy=True))
    waiter = lam.get_waiter("function_updated_v2")
    waiter.wait(FunctionName=function_arn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _wait_for_target_health(ctx, tg_arn: str, target_id: str, predicate, timeout_s: float) -> str:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last_state = "initial"
    while time.monotonic() < deadline:
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": target_id}])
        descriptions = health["TargetHealthDescriptions"]
        if descriptions:
            last_state = descriptions[0]["TargetHealth"]["State"]
            if predicate(last_state):
                return last_state
        time.sleep(5)
    return last_state


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
