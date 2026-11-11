"""drop-invalid-header-fields-strips-the-header-before-the-target."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "drop-invalid-header-fields-strips-the-header-before-the-target"
GROUP = 'data-plane'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


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


def _http(ctx, url, *, method="GET", headers=None, timeout=20):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _default_vpc_and_subnets(ctx, num_subnets=2):
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
        # The ALB's ENIs hold this group until they are released, so the delete retries
        # DependencyViolation every 2 s; an already-deleted group counts as gone.
        deadline = time.monotonic() + 120.0
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

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
    """Create an ALB and register its waited teardown immediately (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(
        Name=name, Subnets=subnet_ids, Type="application",
        Scheme="internal", Tags=list(_TAGS),
    )
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


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
    return listener


def _fixed(body, status="200"):
    return [{"Type": "fixed-response", "FixedResponseConfig": {
        "StatusCode": status, "ContentType": "text/plain", "MessageBody": body}}]


def _create_rule(ctx, listener_arn, priority, path_values, body, status="200"):
    elb = ctx.client("elbv2")
    rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=priority,
        Conditions=[{"Field": "path-pattern",
                     "PathPatternConfig": {"Values": list(path_values)}}],
        Actions=_fixed(body, status), Tags=list(_TAGS),
    ))["Rules"][0]
    arn = rule["RuleArn"]

    def _drop_rule():
        try:
            elb.delete_rule(RuleArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RuleNotFound":
                raise
            return

    ctx.on_cleanup(_drop_rule)
    return rule


def _wait_for_body(ctx, url, expected, *, timeout_s=300, headers=None):
    """Poll (bounded) until the load balancer serves exactly `expected` (body, or (status, body)).

    Configuration changes reach the data plane asynchronously.
    """
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body.strip()[:40]}")
        return (status, body)

    def matches(r):
        if r is None:
            return False
        if isinstance(expected, tuple):
            return (r[0], r[1].strip()) == expected
        return r[1].strip() == expected

    return _poll_until(
        probe, matches, timeout_s=timeout_s, interval_s=5,
        description=f"load balancer serving {expected!r} at {url} (observed: {seen[-8:]})",
    )
_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


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


def _create_lambda(ctx, role_arn, source, *, timeout=20):
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
                Code={"ZipFile": buf.getvalue()}, Timeout=timeout, MemorySize=128,
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
    logs = ctx.client("logs")
    # The log group is minted by the SERVICE on first invocation, so its delete is registered
    # here and tolerates the not-yet-existing case; without it the group outlives the run.
    ctx.on_cleanup(_safe(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active", timeout_s=120, interval_s=3,
        description=f"lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": arn}


#: Already-gone answers of the deletes this check's teardowns make; in-use answers are retried.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidInstanceID.NotFound", "LoadBalancerNotFound",
    "TargetGroupNotFound", "ListenerNotFound", "TrustStoreNotFound", "ResourceNotFoundException",
    "NoSuchBucket", "NoSuchKey",
})
_IN_USE = frozenset({"ResourceInUse", "ResourceInUseException", "DependencyViolation"})


def _safe(fn):
    """Teardown call: an already-gone resource counts as deleted, an in-use one is retried every
    2 s, anything else raises."""
    def _wrapped():
        deadline = time.monotonic() + 180.0
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in _GONE:
                    return
                if code not in _IN_USE or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _allow_elb_invoke(ctx, fn_name, tg_arn):
    lam = ctx.client("lambda")
    try:
        lam.add_permission(
            FunctionName=fn_name, StatementId="elbv2-invoke",
            Action="lambda:InvokeFunction",
            Principal="elasticloadbalancing.amazonaws.com", SourceArn=tg_arn,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # A target group stays ResourceInUse until the listener or rule forwarding to it is gone.
        deadline = time.monotonic() + 40.0
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop_tg)
    return tg


def _forward(target_groups, sticky=None):
    cfg = {"TargetGroups": target_groups}
    if sticky is not None:
        cfg["TargetGroupStickinessConfig"] = sticky
    return [{"Type": "forward", "ForwardConfig": cfg}]


def _lambda_target_registered(ctx, tg_arn, fn_arn):
    """Confirm the Lambda target is in the group.

    Lambda target groups have health checks off by default, so the state stays 'unused', never
    'healthy'; the caller polls readiness on the data plane instead.
    """
    elb = ctx.client("elbv2")
    ids = {d["Target"]["Id"] for d in elb.describe_target_health(
        TargetGroupArn=tg_arn)["TargetHealthDescriptions"]}
    assert fn_arn in ids, (
        f"lambda {fn_arn!r} is not registered in {tg_arn}: describe_target_health lists "
        f"{sorted(ids)!r}"
    )


def _set_lb_attribute(ctx, lb_arn, key, value):
    """Set one load balancer attribute and poll until it reads back."""
    elb = ctx.client("elbv2")
    _retry_throttled(lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn, Attributes=[{"Key": key, "Value": value}]))
    _poll_until(
        lambda: {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(
            LoadBalancerArn=lb_arn)["Attributes"]}.get(key),
        lambda v: v == value, timeout_s=120, interval_s=3,
        description=f"load balancer attribute {key} reading back {value!r}",
    )


def _error(fn):
    """Return the AWS error (code, message), or raise if the call unexpectedly succeeded.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )
_ECHO_FN_SRC = """
import json


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "statusDescription": "200 OK",
        "isBase64Encoded": False,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "headers": event.get("headers") or {},
            "multiValueHeaders": event.get("multiValueHeaders") or {},
        }),
    }
"""


def _echo(ctx, url, headers):
    """One request through the load balancer; returns (status, the request headers the target
    echoes back, lowercased)."""
    status, _hdrs, body = _http(ctx, url, headers=headers)
    if status != 200:
        return status, None
    payload = json.loads(body)
    got = payload.get("headers") or {}
    return status, {k.lower(): v for k, v in got.items()}


def _poll_echo(ctx, url, headers, predicate, description, *, timeout_s=240):
    """Poll (bounded) until the target's echoed headers satisfy `predicate`.

    An attribute change reaches the data plane asynchronously and applies to new connections.
    """
    seen = []

    def probe():
        try:
            status, got = _echo(ctx, url, headers)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{sorted(got or {})}")
        if got is None:
            return None
        return got

    return _poll_until(
        probe, lambda g: g is not None and predicate(g),
        timeout_s=timeout_s, interval_s=5,
        description=f"{description} (observed: {seen[-6:]})",
    )


_ATTR = "routing.http.drop_invalid_header_fields.enabled"
_BAD = "x_sim2real_bad"
_GOOD = "X-Sim2Real-Good"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """With drop_invalid_header_fields on, the ALB strips an underscore header but delivers a valid
    one and still answers 200; with it off both arrive. A non-boolean value is refused, unstored.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes
    """
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    sg_id = _open_http_sg(ctx, vpc_id, 80)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    lb_arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(ctx, lb_arn)

    def _stored():
        return {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(
            LoadBalancerArn=lb_arn)["Attributes"]}.get(_ATTR)

    before_malformed = _stored()
    malformed_code, malformed_message = _error(lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn, Attributes=[{"Key": _ATTR, "Value": "yes-please"}]))
    assert malformed_code == "ValidationError", (
        f"a non-boolean value for {_ATTR} was rejected with {malformed_code!r}, "
        f"expected ValidationError"
    )
    expected_malformed = f"The value of '{_ATTR}' must be 'true' or 'false', but was 'yes-please'"
    assert malformed_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed_message!r}"
    )
    assert _stored() == before_malformed, (
        f"the refused value was stored anyway: {_ATTR} now reads {_stored()!r}, "
        f"was {before_malformed!r}"
    )

    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda(ctx, role_arn, _ECHO_FN_SRC)
    tg = _create_target_group(ctx, TargetType="lambda")
    _allow_elb_invoke(ctx, fn["name"], tg["TargetGroupArn"])
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": fn["arn"]}]))
    _lambda_target_registered(ctx, tg["TargetGroupArn"], fn["arn"])

    listener = _create_listener(
        ctx, lb_arn, Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )
    assert listener["ListenerArn"], f"listener not created: {listener!r}"

    url = f"http://{lb['DNSName']}/"
    req_headers = {_BAD: "dropped", _GOOD: "kept"}

    _poll_echo(ctx, url, req_headers, lambda g: _GOOD.lower() in g,
               "the echoing Lambda target answering through the load balancer")

    _set_lb_attribute(ctx, lb_arn, _ATTR, "true")
    dropped_headers_lower = _poll_echo(
        ctx, url, req_headers, lambda g: _BAD not in g,
        f"{_ATTR}=true removing {_BAD!r} from the target's view",
    )
    dropped_status, _hdrs, _body = _http(ctx, url, headers=req_headers)
    assert dropped_status == 200, (
        f"the request itself was rejected with HTTP {dropped_status!r}; "
        f"{_ATTR} must strip the header, not fail the request"
    )
    assert _BAD not in dropped_headers_lower, (
        f"the underscore header reached the target with {_ATTR} enabled: "
        f"{sorted(dropped_headers_lower)!r}"
    )
    assert dropped_headers_lower.get(_GOOD.lower()) == "kept", (
        f"the valid header sent in the same request did not reach the target: "
        f"{sorted(dropped_headers_lower)!r}"
    )

    # POSITIVE CONTROL: with the attribute off, the same request delivers both headers.
    _set_lb_attribute(ctx, lb_arn, _ATTR, "false")
    kept_headers_lower = _poll_echo(
        ctx, url, req_headers, lambda g: _BAD in g,
        f"{_ATTR}=false delivering {_BAD!r} to the target again",
    )
    assert kept_headers_lower.get(_BAD) == "dropped", (
        f"with the attribute false the underscore header still did not reach the target: "
        f"{sorted(kept_headers_lower)!r} — the drop is not attributable to the attribute"
    )
    assert kept_headers_lower.get(_GOOD.lower()) == "kept", (
        f"the control request lost the valid header too: {sorted(kept_headers_lower)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
