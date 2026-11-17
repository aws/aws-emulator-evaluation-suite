"""xamzn-trace-id-generated-and-preserved-toward-the-target."""
from __future__ import annotations

import io
import json
import re
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xamzn-trace-id-generated-and-preserved-toward-the-target"
GROUP = 'data-plane'
SERVICES = ['elbv2', 'lambda', 'iam']

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


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
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_retrying(fn, *, gone, busy=(), timeout_s=0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _http(ctx, url, *, headers=None, timeout=20):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method="GET", headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _shared_vpc_and_subnets(ctx, num_subnets=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this region to place an internet-facing ALB in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    per_az = {}
    for sub in sorted(subnets, key=lambda s: s["SubnetId"]):
        per_az.setdefault(sub["AvailabilityZone"], sub["SubnetId"])
    subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
    if len(subnet_ids) < num_subnets:
        raise AssertionError(
            f"shared network VPC {vpc_id} exposes {len(subnet_ids)} AZ subnets, need {num_subnets}"
        )
    return vpc_id, subnet_ids


def _open_http_sg(ctx, vpc_id, port=80):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        _delete_retrying(lambda: ec2.delete_security_group(GroupId=sg_id),
                          gone={"InvalidGroup.NotFound"}, busy={"DependencyViolation"}, timeout_s=300)

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()],
        }],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(Name=name, Subnets=subnet_ids, Type="application", Scheme="internal", Tags=list(_TAGS))
    params.update(kwargs)
    lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=10,
        description="load balancer reaching a terminal provisioning state",
    )
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        _delete_retrying(lambda: elb.delete_target_group(TargetGroupArn=arn),
                          gone={"TargetGroupNotFound"}, busy={"ResourceInUse"}, timeout_s=60)

    ctx.on_cleanup(_drop_tg)
    return tg


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
    return listener


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    )["Role"]["Arn"]

    def _drop_role():
        try:
            for pn in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=name, PolicyName=pn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_drop_role)
    return arn


def _create_lambda(ctx, role_arn, source):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    deadline = time.monotonic() + 90
    arn = None
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=20, MemorySize=128,
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidParameterValueException",) or "cannot be assumed" in str(exc):
                last = exc
                time.sleep(4)
                continue
            raise
    assert arn is not None, f"lambda {name} not created: {last!r}"
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active", timeout_s=120, interval_s=3,
        description=f"lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": arn}


def _register_lambda_target_awaiting_invoke_permission(elb, tg_arn, target_id, timeout_s=60):
    """RegisterTargets checks lambda:InvokeFunction up front, and the resource policy
    add_permission just granted propagates with a short lag."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": target_id}])
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "AccessDenied" and "does not have permission to invoke" in str(exc):
                last = exc
                time.sleep(3)
                continue
            raise
    raise last


def _try_trace_header(ctx, url, *, headers, seen):
    try:
        status, body = _http(ctx, url, headers=headers)
    except (urllib.error.URLError, OSError) as exc:
        seen.append(f"<transport: {exc}>")
        return None
    seen.append(f"{status}:{body[:80]}")
    if status != 200:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def _wait_for_trace_header(ctx, url, *, headers, timeout_s=300, description=""):
    seen = []
    got = _poll_until(
        lambda: _try_trace_header(ctx, url, headers=headers, seen=seen),
        lambda r: r is not None and "trace_id_header" in r,
        timeout_s=timeout_s, interval_s=5,
        description=description or f"ALB forwarding to the Lambda target at {url} (observed: {seen[-6:]})",
    )
    return got["trace_id_header"]


def _parse_fields(value):
    """{field: value} for a ``Field=value;Field=value`` X-Amzn-Trace-Id header."""
    fields = {}
    for part in value.split(";"):
        key, _, val = part.partition("=")
        fields[key] = val
    return fields
# ===== end helpers =====

_FN_SRC = '''
import json


def lambda_handler(event, context):
    headers = event.get("headers") or {}
    return {
        "statusCode": 200,
        "statusDescription": "200 OK",
        "isBase64Encoded": False,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"trace_id_header": headers.get("x-amzn-trace-id")}),
    }
'''

_SELF_PATTERN = re.compile(r"^1-[0-9a-f]{8}-[0-9a-f]{24}$")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The ALB adds an X-Amzn-Trace-Id header with a generated Root field when the client sends
    none, and when the client sends one with a Root field the ALB inserts a Self field while
    preserving the Root field and any custom field unchanged.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-request-tracing.html
    """
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")
    vpc_id, subnet_ids = _shared_vpc_and_subnets(ctx)
    sg_id = _open_http_sg(ctx, vpc_id, 80)

    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda(ctx, role_arn, _FN_SRC)

    lb = _create_load_balancer(ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(ctx, TargetType="lambda")
    tg_arn = tg["TargetGroupArn"]
    lam.add_permission(
        FunctionName=fn["name"], StatementId="elbv2-invoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com", SourceArn=tg_arn,
    )
    _register_lambda_target_awaiting_invoke_permission(elb, tg_arn, fn["arn"])
    _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    base = f"http://{lb['DNSName']}"

    # 1. No client header: the ALB generates one with a Root field in the documented format.
    generated = _wait_for_trace_header(
        ctx, base, headers={},
        description="ALB generating an X-Amzn-Trace-Id header for a request that sent none",
    )
    assert generated is not None, "the target received no X-Amzn-Trace-Id header at all"
    gen_fields = _parse_fields(generated)
    assert set(gen_fields) == {"Root"}, (
        f"generated header had fields {sorted(gen_fields)}, expected only Root: {generated!r}"
    )
    assert _SELF_PATTERN.match(gen_fields["Root"]), (
        f"generated Root field {gen_fields['Root']!r} does not match version-time-id"
    )

    # 2. Client sends a Root field: the ALB preserves it exactly and inserts its own Self field.
    client_root = "1-6a11b2c3-0123456789abcdef01234567"
    with_root = _try_trace_header(
        ctx, base, headers={"X-Amzn-Trace-Id": f"Root={client_root}"}, seen=[],
    )
    assert with_root is not None, "no response to the request carrying a client Root field"
    root_fields = _parse_fields(with_root["trace_id_header"])
    assert set(root_fields) == {"Root", "Self"}, (
        f"header with a client Root had fields {sorted(root_fields)}, expected Root and Self: "
        f"{with_root['trace_id_header']!r}"
    )
    assert root_fields["Root"] == client_root, (
        f"client Root field was changed to {root_fields['Root']!r}, expected it preserved as "
        f"{client_root!r}"
    )
    assert _SELF_PATTERN.match(root_fields["Self"]), (
        f"inserted Self field {root_fields['Self']!r} does not match version-time-id"
    )

    # 3. A custom field alongside Root survives the round trip too.
    with_custom = _try_trace_header(
        ctx, base,
        headers={"X-Amzn-Trace-Id": f"Root={client_root};appname=sim2real-behav"}, seen=[],
    )
    assert with_custom is not None, "no response to the request carrying a client Root and custom field"
    custom_fields = _parse_fields(with_custom["trace_id_header"])
    assert set(custom_fields) == {"Root", "Self", "appname"}, (
        f"header with a custom field had fields {sorted(custom_fields)}, expected Root, Self and "
        f"appname: {with_custom['trace_id_header']!r}"
    )
    assert custom_fields["Root"] == client_root, custom_fields
    assert custom_fields["appname"] == "sim2real-behav", (
        f"custom appname field was changed to {custom_fields['appname']!r}, expected it "
        f"preserved as 'sim2real-behav'"
    )
    assert _SELF_PATTERN.match(custom_fields["Self"]), (
        f"inserted Self field {custom_fields['Self']!r} does not match version-time-id"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
