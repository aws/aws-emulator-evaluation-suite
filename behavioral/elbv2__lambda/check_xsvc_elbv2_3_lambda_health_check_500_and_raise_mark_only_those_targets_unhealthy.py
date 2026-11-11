"""xsvc-elbv2-3-lambda-health-check-500-and-raise-mark-only-those-targets-unhealthy."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-elbv2-3-lambda-health-check-500-and-raise-mark-only-those-targets-unhealthy"
GROUP = "cross-service"
SERVICES = ["elbv2", "lambda"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_ELB_PRINCIPAL = "elasticloadbalancing.amazonaws.com"
_CIDR = "10.184.0.0/16"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


def _retry_throttled(fn, attempts=5):
    delays = [3, 6, 12, 24, 30]
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(delays[min(i, len(delays) - 1)])
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retrying_delete(what, fn, *, attempts=30, interval_s=8):
    """Teardown-only: retry through DependencyViolation (ALB ENIs release late). A delete that
    never converges raises, so it cannot vanish silently."""
    def _wrapped():
        last = None
        for _ in range(attempts):
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if (code.endswith("NotFound") or code.endswith(".NotFound")
                        or code in ("ResourceNotFoundException", "TargetGroupNotFound",
                                    "LoadBalancerNotFound")):
                    return
                last = exc
            time.sleep(interval_s)
        raise RuntimeError(f"{what}: {last!r}")

    return _wrapped


def _http(ctx, url, *, timeout=30):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method="GET", headers=_route)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _probe(ctx, url):
    try:
        return _http(ctx, url)
    except (urllib.error.URLError, OSError) as exc:
        return (None, f"<transport: {type(exc).__name__}: {exc}>")


def _own_public_vpc(ctx, n_subnets=2):
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _spec(kind):
        return [{"ResourceType": kind, "Tags": list(_TAGS)}]

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(_retrying_delete(f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs ({azs!r}), a load balancer needs {n_subnets}")
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_spec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(_retrying_delete(
        f"igw {igw_id}", lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(_retrying_delete(
        f"igw attachment {igw_id}",
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))
    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_spec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_retrying_delete(
        f"route table {rtb_id}", lambda: ec2.delete_route_table(RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    base = _CIDR.split(".")
    subnets = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{base[0]}.{base[1]}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=_spec("subnet"))["Subnet"]["SubnetId"]
        ctx.on_cleanup(_retrying_delete(f"subnet {sid}", lambda s=sid: ec2.delete_subnet(SubnetId=s)))
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_retrying_delete(
            f"rtb association {assoc}",
            lambda a=assoc: ec2.disassociate_route_table(AssociationId=a), attempts=3))
        subnets.append(sid)
    return vpc_id, subnets


def _open_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-xsvc-lbsg-"), Description="sim2real alb ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(_retrying_delete(
        f"security group {sg_id}", lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}])
    return sg_id


def _create_load_balancer(ctx, subnets, sg_id):
    elb = ctx.client("elbv2")
    name = _clamp_name(ctx.unique_name("sim2real-xsvc-lb-"))
    lb = _retry_throttled(lambda: elb.create_load_balancer(
        Name=name, Subnets=subnets, SecurityGroups=[sg_id], Scheme="internet-facing",
        Type="application", IpAddressType="ipv4", Tags=list(_TAGS)))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        _retrying_delete(f"load balancer {arn}",
                         lambda: elb.delete_load_balancer(LoadBalancerArn=arn), attempts=5)()
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(4)
        raise RuntimeError(f"load balancer {arn} still described after 360s")

    ctx.on_cleanup(_drop_lb)
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] != "provisioning", timeout_s=600, interval_s=2,
        description=f"load balancer {name} leaving provisioning")
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST, Tags=list(_TAGS))["Role"]["Arn"]
    ctx.on_cleanup(_retrying_delete(f"role {name}", lambda: iam.delete_role(RoleName=name),
                                    attempts=3))
    return arn


def _reap_log_group_loop(ctx, fn_name):
    """Registered before create_function so LIFO runs it after the delete.

    A buffered log flush can recreate /aws/lambda/<fn> after one delete, so this retries."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"

    def _reap():
        for _ in range(4):
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            time.sleep(10)
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups") or []
            if not any(g["logGroupName"] == group for g in found):
                return
        raise RuntimeError(f"log group {group} reappeared after 4 delete rounds")

    ctx.on_cleanup(_reap)


def _create_lambda(ctx, role_arn, source):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    _reap_log_group_loop(ctx, name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=10, MemorySize=128,
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
        except ClientError as exc:
            # IAM propagation of the freshly created execution role only.
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    arn = _poll_until(_try_create, lambda a: a is not None, timeout_s=180, interval_s=5,
                      description=f"lambda {name} accepting the freshly created execution role")
    ctx.on_cleanup(_retrying_delete(f"function {name}",
                                    lambda: lam.delete_function(FunctionName=name), attempts=3))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name).get("State"),
                lambda s: s == "Active", timeout_s=180, interval_s=3,
                description=f"lambda {name} reaching State=Active")
    return name, arn


#: The shortest health-check interval a Lambda target group allows; the timeout must be below it.
_HC_INTERVAL_S = 5


def _lambda_target_group(ctx, health_path):
    elb = ctx.client("elbv2")
    tg = _retry_throttled(lambda: elb.create_target_group(
        Name=_clamp_name(ctx.unique_name("sim2real-xsvc-tg-")), TargetType="lambda",
        HealthCheckEnabled=True, HealthCheckPath=health_path,
        HealthCheckIntervalSeconds=_HC_INTERVAL_S, HealthCheckTimeoutSeconds=_HC_INTERVAL_S - 1,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        Matcher={"HttpCode": "200"}, Tags=list(_TAGS)))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(_retrying_delete(f"target group {arn}",
                                    lambda: elb.delete_target_group(TargetGroupArn=arn),
                                    attempts=15, interval_s=4))
    return tg

# One source for all three functions: /hc/fail answers a well-formed 500, /hc/raise raises (no
# HTTP answer at all), every other path answers 200, so only HealthCheckPath differs.
_FN_SRC = '''
import os


def lambda_handler(event, context):
    path = event.get("path") or ""
    if path.endswith("/hc/raise"):
        raise RuntimeError("sim2real deliberate health-path failure")
    if path.endswith("/hc/fail"):
        return {"statusCode": 500, "statusDescription": "500 Internal Server Error",
                "isBase64Encoded": False, "headers": {"Content-Type": "text/plain"},
                "body": "HEALTH-FAIL"}
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": {"Content-Type": "text/plain"},
            "body": "SERVED-BY " + os.environ["AWS_LAMBDA_FUNCTION_NAME"]}
'''


@tags("concern:data-plane", "dp:endpoint", "plane:data", "axis:happy-path", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A health path returning 500 is ResponseCodeMismatch; one that raises is FailedHealthChecks.

    The sibling on a 200 path goes healthy, and all three targets are still invoked by real traffic.
    """
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")

    vpc_id, subnets = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id)
    role_arn = _create_lambda_role(ctx)
    bad_fn, bad_arn = _create_lambda(ctx, role_arn, _FN_SRC)
    good_fn, good_arn = _create_lambda(ctx, role_arn, _FN_SRC)
    err_fn, err_arn = _create_lambda(ctx, role_arn, _FN_SRC)

    lb = _create_load_balancer(ctx, subnets, sg_id)
    lb_arn, dns = lb["LoadBalancerArn"], lb["DNSName"]

    bad_tg = _lambda_target_group(ctx, "/hc/fail")["TargetGroupArn"]
    good_tg = _lambda_target_group(ctx, "/hc/ok")["TargetGroupArn"]
    err_tg = _lambda_target_group(ctx, "/hc/raise")["TargetGroupArn"]
    for fn_name, fn_arn, tg_arn in ((bad_fn, bad_arn, bad_tg), (good_fn, good_arn, good_tg),
                                    (err_fn, err_arn, err_tg)):
        lam.add_permission(FunctionName=fn_name, StatementId="sim2real-elbv2-invoke",
                           Action="lambda:InvokeFunction", Principal=_ELB_PRINCIPAL,
                           SourceArn=tg_arn)
        _retry_throttled(lambda t=tg_arn, a=fn_arn: elb.register_targets(
            TargetGroupArn=t, Targets=[{"Id": a}]))
        ctx.on_cleanup(_retrying_delete("deregister lambda", lambda t=tg_arn, a=fn_arn:
                                        elb.deregister_targets(TargetGroupArn=t,
                                                               Targets=[{"Id": a}]), attempts=3))

    # Health checks only run for a target group a listener uses, so all three are attached: the
    # good one as the default action, the others behind path rules.
    listener_arn = _retry_throttled(lambda: elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": good_tg}]))["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_retrying_delete("listener", lambda: elb.delete_listener(ListenerArn=listener_arn),
                                    attempts=3))
    rule_arn = elb.create_rule(
        ListenerArn=listener_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/bad/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": bad_tg}])["Rules"][0]["RuleArn"]
    ctx.on_cleanup(_retrying_delete("listener rule", lambda: elb.delete_rule(RuleArn=rule_arn),
                                    attempts=3))
    err_rule_arn = elb.create_rule(
        ListenerArn=listener_arn, Priority=20,
        Conditions=[{"Field": "path-pattern", "Values": ["/err/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": err_tg}])["Rules"][0]["RuleArn"]
    ctx.on_cleanup(_retrying_delete("listener rule", lambda: elb.delete_rule(RuleArn=err_rule_arn),
                                    attempts=3))

    def _health(tg_arn, fn_arn):
        d = elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        assert [t["Target"]["Id"] for t in d] == [fn_arn], (
            f"target group {tg_arn} lists {d!r}, expected exactly the Lambda {fn_arn!r}")
        return d[0]["TargetHealth"]

    seen = {"bad": [], "good": [], "err": []}

    def _all():
        b, g, e = (_health(bad_tg, bad_arn), _health(good_tg, good_arn),
                   _health(err_tg, err_arn))
        seen["bad"].append((b.get("State"), b.get("Reason")))
        seen["good"].append((g.get("State"), g.get("Reason")))
        seen["err"].append((e.get("State"), e.get("Reason")))
        return b, g, e

    bad_h, good_h, err_h = _poll_until(
        _all, lambda r: (r[0].get("State"), r[1].get("State"), r[2].get("State")) == (
            "unhealthy", "healthy", "unhealthy"),
        timeout_s=600, interval_s=2,
        description=f"500/raise targets unhealthy and good target healthy (observed {seen!r})")
    print(f"[health] bad={bad_h!r} good={good_h!r} err={err_h!r} transitions={seen!r}")

    assert bad_h.get("Reason") == "Target.ResponseCodeMismatch", (
        f"the target whose health path answers 500 is unhealthy with reason "
        f"{bad_h.get('Reason')!r} ({bad_h!r}), expected 'Target.ResponseCodeMismatch'")
    assert bad_h.get("Description") == "Health checks failed with these codes: [500]", (
        f"the 500 target's Description is {bad_h.get('Description')!r}, expected it to name the "
        f"code the function returned: 'Health checks failed with these codes: [500]'")
    assert err_h.get("Reason") == "Target.FailedHealthChecks", (
        f"the target whose health path raises is unhealthy with reason {err_h.get('Reason')!r} "
        f"({err_h!r}), expected 'Target.FailedHealthChecks' — there is no HTTP code to mismatch")
    assert "Reason" not in good_h, (
        f"the healthy sibling carries a reason {good_h!r}; a healthy target has none")
    for label in ("bad", "err"):
        assert all(s != "healthy" for s, _ in seen[label]), (
            f"the {label} target was reported healthy at some point: {seen[label]!r}")

    # The verdict is stable, not a flap: sampled every 2 s for three more health intervals.
    stable_until = time.monotonic() + 3 * _HC_INTERVAL_S
    while True:
        time.sleep(2)
        b, g, e = _all()
        assert (b.get("State"), b.get("Reason")) == ("unhealthy", "Target.ResponseCodeMismatch"), (
            f"the 500 target left unhealthy/Target.ResponseCodeMismatch: {b!r}")
        assert (e.get("State"), e.get("Reason")) == ("unhealthy", "Target.FailedHealthChecks"), (
            f"the raising target left unhealthy/Target.FailedHealthChecks: {e!r}")
        assert g.get("State") == "healthy", f"the good sibling left healthy: {g!r}"
        if time.monotonic() >= stable_until:
            break

    # Real traffic still reaches both functions — the health verdict concerns the HEALTH path.
    good_resp = _poll_until(lambda: _probe(ctx, f"http://{dns}/serve"),
                            lambda r: r[0] == 200, timeout_s=180, interval_s=5,
                            description="the ALB serving the healthy Lambda target")
    assert good_resp == (200, f"SERVED-BY {good_fn}"), (
        f"default route returned {good_resp!r}, expected (200, 'SERVED-BY {good_fn}')")
    bad_resp = _probe(ctx, f"http://{dns}/bad/serve")
    assert bad_resp == (200, f"SERVED-BY {bad_fn}"), (
        f"/bad/serve returned {bad_resp!r}, expected (200, 'SERVED-BY {bad_fn}') — the only target "
        f"in that group is unhealthy, so the ALB fails open and still invokes it")
    err_resp = _probe(ctx, f"http://{dns}/err/serve")
    assert err_resp == (200, f"SERVED-BY {err_fn}"), (
        f"/err/serve returned {err_resp!r}, expected (200, 'SERVED-BY {err_fn}') — only the health "
        f"path raises, and the unhealthy group fails open")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
