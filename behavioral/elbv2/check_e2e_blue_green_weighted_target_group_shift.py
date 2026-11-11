"""e2e-blue-green-weighted-target-group-shift."""
from __future__ import annotations

import http.client
import urllib.parse
import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-blue-green-weighted-target-group-shift"
GROUP = "e2e"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A weighted forward rule across two Lambda-backed target groups actually routes live HTTP
    traffic to whichever target group carries the nonzero weight, and shifting the weights from
    100/0 to 0/100 flips which target answers every subsequent request."""
    elbv2 = ctx.client("elbv2")
    role_arn = _create_lambda_role(ctx)
    blue_arn = _create_color_lambda(ctx, role_arn, "blue")
    green_arn = _create_color_lambda(ctx, role_arn, "green")

    tg_blue = elbv2.create_target_group(
        Name=_short_name("sim2real-blue"), TargetType="lambda", HealthCheckEnabled=True, Tags=_tags_kv()
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_target_group(TargetGroupArn=tg_blue)))
    tg_green = elbv2.create_target_group(
        Name=_short_name("sim2real-green"), TargetType="lambda", HealthCheckEnabled=True, Tags=_tags_kv()
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_target_group(TargetGroupArn=tg_green)))

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=blue_arn,
        StatementId="AllowELBInvokeBlue",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_blue,
    )
    lam.add_permission(
        FunctionName=green_arn,
        StatementId="AllowELBInvokeGreen",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_green,
    )

    elbv2.register_targets(TargetGroupArn=tg_blue, Targets=[{"Id": blue_arn}])
    elbv2.register_targets(TargetGroupArn=tg_green, Targets=[{"Id": green_arn}])

    vpc_id, subnet_ids = _get_default_vpc_subnets(ctx)
    sg_id = _create_open_security_group(ctx, vpc_id, [80])
    lb_arn = elbv2.create_load_balancer(
        Name=_short_name("sim2real-bg"),
        Subnets=subnet_ids[:2],
        SecurityGroups=[sg_id],
        Scheme="internet-facing",
        Type="application",
        Tags=_tags_kv(),
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    dns_name = _wait_for_lb_active(ctx, lb_arn)

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "404", "ContentType": "text/plain", "MessageBody": "none"},
            }
        ],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=1,
        Conditions=[{"Field": "path-pattern", "Values": ["/*"]}],
        Actions=[
            {
                "Type": "forward",
                "ForwardConfig": {
                    "TargetGroups": [
                        {"TargetGroupArn": tg_blue, "Weight": 100},
                        {"TargetGroupArn": tg_green, "Weight": 0},
                    ]
                },
            }
        ],
    )["Rules"][0]["RuleArn"]

    for tg_arn in (tg_blue, tg_green):
        _wait_for_target_healthy(ctx, tg_arn)

    # Weight 100/0 is deterministic: every request must land on blue.
    for _ in range(4):
        status, body = _poll_http_get(ctx, dns_name, 80, "/")
        assert status == 200, f"expected 200 with weight 100/0, got {status}"
        assert body == "blue", f"expected blue with weight 100/0, got {body!r}"

    elbv2.modify_rule(
        RuleArn=rule_arn,
        Actions=[
            {
                "Type": "forward",
                "ForwardConfig": {
                    "TargetGroups": [
                        {"TargetGroupArn": tg_blue, "Weight": 0},
                        {"TargetGroupArn": tg_green, "Weight": 100},
                    ]
                },
            }
        ],
    )

    updated_rule = elbv2.describe_rules(RuleArns=[rule_arn])["Rules"][0]
    weights = {
        tg["TargetGroupArn"]: tg["Weight"]
        for tg in updated_rule["Actions"][0]["ForwardConfig"]["TargetGroups"]
    }
    assert weights[tg_blue] == 0 and weights[tg_green] == 100, f"unexpected weights after shift: {weights}"

    # Propagation to ALB nodes isn't instant; poll until routing has visibly flipped, then pin it.
    deadline = time.monotonic() + 60.0
    flipped = False
    while time.monotonic() < deadline:
        _, body = _poll_http_get(ctx, dns_name, 80, "/", timeout_s=20.0)
        if body == "green":
            flipped = True
            break
        time.sleep(3.0)
    assert flipped, "routing never shifted to green after the weight change"
    for _ in range(4):
        status, body = _poll_http_get(ctx, dns_name, 80, "/", timeout_s=20.0)
        assert status == 200, f"expected 200 with weight 0/100, got {status}"
        assert body == "green", f"expected green with weight 0/100, got {body!r}"

    for tg_arn in (tg_blue, tg_green):
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        assert len(health) == 1 and health[0]["TargetHealth"]["State"] == "healthy", (
            f"expected a single healthy lambda target on {tg_arn}, got {health}"
        )

    elbv2.delete_rule(RuleArn=rule_arn)
    for tg_arn, fn_arn in ((tg_blue, blue_arn), (tg_green, green_arn)):
        elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])
        elbv2.delete_target_group(TargetGroupArn=tg_arn)
        code, message = _error(lambda tg=tg_arn: elbv2.describe_target_groups(TargetGroupArns=[tg]))
        assert code == "TargetGroupNotFound", f"expected TargetGroupNotFound after delete, got {code!r}"
        assert message == "One or more target groups not found", (
            f"expected the exact not-found message after delete, got {message!r}"
        )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _short_name(prefix: str, max_len: int = 32) -> str:
    suffix = uuid.uuid4().hex[:10]
    name = f"{prefix}-{suffix}"
    return name[:max_len].rstrip("-")


def _error(fn) -> tuple[str | None, str | None]:
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ListenerNotFound",
            "LoadBalancerNotFound",
            "NoSuchEntity",
            "ResourceNotFoundException",
            "TargetGroupNotFound",
        ):
            raise


def _get_default_vpc_subnets(ctx, min_azs: int = 2) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to provision a load balancer against")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < min_azs:
        raise AssertionError(
            f"shared network VPC has subnets in only {len(by_az)} AZ(s); need at least {min_azs} for an ALB"
        )
    return vpc_id, sorted(by_az.values())


def _create_open_security_group(ctx, vpc_id: str, ports: list[int]) -> str:
    ec2 = ctx.client("ec2")
    sg_name = _short_name("sim2real-sg", max_len=64)
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real elbv2 behavioral test",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    def _cleanup_sg() -> None:
        deadline = time.monotonic() + 180.0
        while time.monotonic() < deadline:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code == "DependencyViolation":
                    time.sleep(5.0)
                    continue
                raise

    ctx.on_cleanup(_cleanup_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
            for p in ports
        ],
    )
    return sg_id


def _wait_for_lb_active(ctx, lb_arn: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        last_state = lb["State"]["Code"]
        if last_state == "active":
            return lb["DNSName"]
        if last_state == "failed":
            raise AssertionError(f"load balancer {lb_arn} entered failed state")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer never became active (last state={last_state})")


def _wait_for_target_healthy(ctx, tg_arn: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        if health:
            last_state = health[0]["TargetHealth"]["State"]
            if last_state == "healthy":
                return
        time.sleep(interval_s)
    raise AssertionError(f"lambda target on {tg_arn} never reported healthy (last state={last_state})")


def _poll_http_get(
    ctx, host: str, port: int, path: str, timeout_s: float = 180.0, interval_s: float = 5.0
) -> tuple[int, str]:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        conn = None
        try:
            _url, _route = ctx.endpoint_route(f"http://{host}:{port}")
            _t = urllib.parse.urlsplit(_url)
            conn = http.client.HTTPConnection(_t.hostname, _t.port or 80, timeout=10)
            conn.request("GET", path, headers=_route)
            resp = conn.getresponse()
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            return status, body
        except (OSError, http.client.HTTPException) as exc:  # DNS and ENIs settle after the listener is created
            last_exc = exc
            time.sleep(interval_s)
        finally:
            if conn is not None:
                conn.close()
    raise AssertionError(f"never got an HTTP response from {host}:{port}{path}: {last_exc}")


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-elbv2-lambda-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return role_arn


def _make_lambda_zip(color: str) -> bytes:
    code = (
        "def handler(event, context):\n"
        "    return {\n"
        '        "statusCode": 200,\n'
        '        "statusDescription": "200 OK",\n'
        '        "isBase64Encoded": False,\n'
        '        "headers": {"Content-Type": "text/plain"},\n'
        f'        "body": "{color}",\n'
        "    }\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_color_lambda(ctx, role_arn: str, color: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(f"sim2real-behav-elbv2-{color}-")
    zip_bytes = _make_lambda_zip(color)

    deadline = time.monotonic() + 30.0
    last_exc: ClientError | None = None
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            fn_arn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    if fn_arn is None:
        raise AssertionError(f"could not create lambda function {fn_name}: {last_exc}")
    ctx.on_cleanup(lambda: _safe_call(lambda: lam.delete_function(FunctionName=fn_name)))

    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name)["State"]
        if state == "Active":
            return fn_arn
        time.sleep(2.0)
    raise AssertionError(f"lambda function {fn_name} never became Active")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
