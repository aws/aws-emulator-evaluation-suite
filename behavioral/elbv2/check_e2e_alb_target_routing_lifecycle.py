"""e2e-alb-target-routing-lifecycle."""
from __future__ import annotations

import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-alb-target-routing-lifecycle"
GROUP = "e2e"
SERVICES = ["elbv2"]
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0
#: Managed tags on every created resource, so a leaked one is visible to a tag search.
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-elbv2"}
_TAG_LIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]


def _tag_spec(resource_type: str) -> list[dict[str, Any]]:
    return [{"ResourceType": resource_type, "Tags": _TAG_LIST}]

#: The function echoes a per-run nonce baked into its code and the request path, so the body can
#: only come from a real invocation of this run's function with this request.
_HANDLER_CODE = """
NONCE = {nonce!r}


def handler(event, context):
    return {{
        "statusCode": 200,
        "statusDescription": "200 OK",
        "isBase64Encoded": False,
        "headers": {{"Content-Type": "text/plain"}},
        "body": NONCE + ":" + event.get("path", ""),
    }}
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An internet-facing ALB routes a live HTTP request to a healthy Lambda target, then after
    deletion the load balancer, target group and function each refuse use with exact errors.
    """
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    lam = ctx.client("lambda")

    net = _create_network(ctx, ec2, internet_facing=True)

    nonce = ctx.unique_name("n")
    tg_name = ctx.unique_name("sim2real-elbv2-tg-")[:32].rstrip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name,
        TargetType="lambda",
        HealthCheckEnabled=True,
        HealthCheckIntervalSeconds=6,
        HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        Tags=_TAG_LIST,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore(
        ("TargetGroupNotFound",), lambda: _retry_delete(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    ))

    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_lambda_function(ctx, role_arn, nonce)

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="AllowALBInvoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_arn,
    )
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])

    lb_name = ctx.unique_name("sim2real-elbv2-")[:32].rstrip("-")
    lb = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=net["subnet_ids"],
        SecurityGroups=[net["sg_id"]],
        Scheme="internet-facing",
        Type="application",
        Tags=_TAG_LIST,
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    dns_name = lb["DNSName"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]

    elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/health*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )

    _wait_lb_active(elbv2, lb_arn, timeout_s=_budget_s(ctx, POLL_BUDGET_S), ctx=ctx)
    _wait_target_healthy(elbv2, tg_arn, fn_arn, timeout_s=_budget_s(ctx, POLL_BUDGET_S), ctx=ctx)

    # The published DNSName is reached only through the target's mapping of it; the listener is
    # plain HTTP on port 80, so the scheme is explicit, and the Host header names the ALB.
    base = ctx.endpoint_url(f"http://{dns_name}")
    path = f"/probe/{nonce}"
    body = _fetch_http(f"{base}{path}", ctx.http_verify, dns_name,
                       timeout_s=_budget_s(ctx, POLL_BUDGET_S), ctx=ctx)
    assert body == f"{nonce}:{path}", f"expected the Lambda's echo {nonce}:{path!r}, got {body!r}"

    # The load balancer is deleted and gone: unreadable by ARN and name, unusable, unserved.
    _delete_lb_and_wait(elbv2, lb_arn, timeout_s=_budget_s(ctx, POLL_BUDGET_S), ctx=ctx)
    exc = _expect_error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn]), ("LoadBalancerNotFound",))
    message = exc.response["Error"]["Message"]
    assert message == "One or more load balancers not found", f"MSG={message!r}"
    exc = _expect_error(lambda: elbv2.describe_load_balancers(Names=[lb_name]), ("LoadBalancerNotFound",))
    message = exc.response["Error"]["Message"]
    assert message == f"Load balancers '[{lb_name}]' not found", f"MSG={message!r}"
    exc = _expect_error(lambda: elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=8080,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    ), ("LoadBalancerNotFound",))
    message = exc.response["Error"]["Message"]
    assert message == f"Load balancer '{lb_arn}' not found", f"MSG={message!r}"
    _wait_not_served(f"{base}{path}", ctx.http_verify, nonce, dns_name,
                     timeout_s=_budget_s(ctx, POLL_BUDGET_S), ctx=ctx)

    remaining = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"]
    assert remaining and remaining[0]["LoadBalancerArns"] == [], (
        "target group should no longer reference the deleted load balancer"
    )

    # The target group is deleted and gone: unreadable by ARN and name, refuses registration.
    elbv2.delete_target_group(TargetGroupArn=tg_arn)
    exc = _expect_error(lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]), ("TargetGroupNotFound",))
    message = exc.response["Error"]["Message"]
    assert message == "One or more target groups not found", f"MSG={message!r}"
    exc = _expect_error(lambda: elbv2.describe_target_groups(Names=[tg_name]), ("TargetGroupNotFound",))
    message = exc.response["Error"]["Message"]
    assert message == "One or more target groups not found", f"MSG={message!r}"
    exc = _expect_error(lambda: elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}]),
                        ("TargetGroupNotFound",))
    message = exc.response["Error"]["Message"]
    assert message == f"Target groups '{tg_arn}' not found", f"MSG={message!r}"

    # The Lambda target is deleted and gone: unreadable, unlisted, uninvokable.
    lam.delete_function(FunctionName=fn_name)
    _poll_not_found(lambda: lam.get_function(FunctionName=fn_name), ("ResourceNotFoundException",),
                    status=404, timeout_s=_budget_s(ctx, 120.0), ctx=ctx)
    listed = [
        f["FunctionName"] for page in lam.get_paginator("list_functions").paginate()
        for f in page.get("Functions", [])
    ]
    assert fn_name not in listed, f"ListFunctions still lists deleted function {fn_name}"
    exc = _expect_error(lambda: lam.invoke(FunctionName=fn_name, Payload=b"{}"), ("ResourceNotFoundException",),
                        status=404)
    message = exc.response["Error"]["Message"]
    assert message == f"Function not found: {fn_arn}:$LATEST", f"MSG={message!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, a non-empty message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected a non-empty message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _poll_not_found(fn, codes, *, status=400, timeout_s: float = 120.0, ctx=None):
    """Poll fn() (bounded) until it raises one of ``codes``, then grade that refusal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in codes:
                _assert_error(exc, codes, status=status)
                return
            raise
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the deleted resource answering {codes!r}: the run budget "
                                   f"ended first; not graded")
            raise AssertionError(f"still readable {timeout_s:.0f}s after the delete; expected {codes!r}")
        time.sleep(1.0)


def _ignore(codes, call):
    """Teardown call that tolerates the resource already being gone."""
    try:
        call()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)



def _retry_delete(fn, attempts: int = 30, delay: float = 5.0) -> None:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - botocore ClientError shape varies
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in (
                "DependencyViolation",
                "InvalidGroup.InUse",
                "InvalidSubnetID.InUse",
                "InvalidVpcID.InUse",
                "ResourceInUse",
            ):
                last = exc
                time.sleep(delay)
                continue
            raise
    if last:
        raise last


def _create_network(ctx, ec2, internet_facing: bool) -> dict[str, Any]:
    vpc_id = ec2.create_vpc(CidrBlock="10.78.0.0/16", TagSpecifications=_tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones()["AvailabilityZones"]
        if z["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.78.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet"),
        )[
            "Subnet"
        ]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
        if internet_facing:
            ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-elbv2-sg-"),
        Description="sim2real elbv2 behavioral check",
        TagSpecifications=_tag_spec("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
        ],
    )

    if internet_facing:
        igw_id = ec2.create_internet_gateway(
            TagSpecifications=_tag_spec("internet-gateway"),
        )["InternetGateway"]["InternetGatewayId"]
        ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ctx.on_cleanup(
            lambda: _retry_delete(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        )
        rt_id = ec2.create_route_table(
            VpcId=vpc_id, TagSpecifications=_tag_spec("route-table"),
        )["RouteTable"]["RouteTableId"]
        ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
        ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
        for sid in subnet_ids:
            assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
            ctx.on_cleanup(lambda a=assoc_id: ec2.disassociate_route_table(AssociationId=a))

    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-elbv2-lambdarole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAG_LIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _lambda_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn: str, nonce: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-elbv2-fn-")
    code = _lambda_zip(_HANDLER_CODE.format(nonce=nonce))
    last_exc: Exception | None = None
    resp = None
    for _ in range(12):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=10,
                MemorySize=128,
                Tags=dict(_TAGS),
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda function never created (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: _ignore(("ResourceNotFoundException",), lambda: lam.delete_function(FunctionName=name)))
    try:
        lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    except Exception:
        lam.get_waiter("function_active").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name, resp["FunctionArn"]


def _wait_lb_active(elbv2, lb_arn: str, timeout_s: float = POLL_BUDGET_S, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"]
        if state == "active":
            return
        time.sleep(1.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"load balancer {lb_arn} becoming active: the run budget ended "
                           f"first; not graded")
    raise AssertionError(f"load balancer never became active, last state={state}")


def _wait_target_healthy(elbv2, tg_arn: str, target_id: str, timeout_s: float = POLL_BUDGET_S,
                         ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": target_id}])
        state = health["TargetHealthDescriptions"][0]["TargetHealth"]["State"]
        if state == "healthy":
            return
        time.sleep(1.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"target {target_id} becoming healthy: the run budget ended first; "
                           f"not graded")
    raise AssertionError(f"target never became healthy, last state={state}")


def _delete_lb_and_wait(elbv2, lb_arn: str, timeout_s: float = POLL_BUDGET_S, ctx=None) -> None:
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except elbv2.exceptions.LoadBalancerNotFoundException:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except elbv2.exceptions.LoadBalancerNotFoundException:
            return
        time.sleep(1.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"load balancer {lb_arn} being removed: the run budget ended "
                           f"first; not graded")
    raise AssertionError("load balancer was not removed within timeout")


def _fetch_http(url: str, verify, host: str, timeout_s: float = POLL_BUDGET_S, ctx=None) -> str:
    """GET url until it answers 2xx (the ALB DNS name and target may still be settling)."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, headers={"Host": host})
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context(verify)) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, ConnectionError, TimeoutError) as exc:
            last_exc = exc
            time.sleep(1.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"a 2xx answer from {url}: the run budget ended first; not "
                           f"graded")
    if not isinstance(last_exc, urllib.error.HTTPError):
        # Nothing ever answered at the load balancer's DNS name: no listener data plane exists.
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: nothing answered at the ALB listener {url} within "
            f"{timeout_s:.0f}s, so target routing could not be observed at all: {last_exc}"
        )
    raise AssertionError(f"never got a successful HTTP response from {url}: {last_exc}")


def _wait_not_served(url: str, verify, nonce: str, host: str,
                     timeout_s: float = POLL_BUDGET_S, ctx=None) -> None:
    """Poll until the deleted ALB's URL no longer returns this run's Lambda body."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            req = urllib.request.Request(url, headers={"Host": host})
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context(verify)) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, ConnectionError, TimeoutError, OSError):
            return
        if nonce not in body:
            return
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the deleted ALB at {url} going dark: the run budget ended "
                                   f"first; not graded")
            raise AssertionError(f"the deleted ALB still serves the Lambda body at {url}: {body!r}")
        time.sleep(1.0)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
