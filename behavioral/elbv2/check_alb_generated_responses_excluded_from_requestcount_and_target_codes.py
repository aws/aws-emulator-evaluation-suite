"""alb-generated-responses-excluded-from-requestcount-and-target-codes."""
from __future__ import annotations

# AWS behavior this check relies on:
#   H1 RequestCount is NOT incremented for a request served by a fixed-response action, because
#      the load balancer never chose a target ("This metric is only incremented for requests where
#      the load balancer node was able to choose a target" — ALB CloudWatch metrics doc). The
#      B-window assertion `RequestCount == 0` rests entirely on H1.
#   H2 HTTPCode_Target_4XX_Count is NOT incremented by an ALB-generated 404 (fixed-response) and IS
#      incremented by a target-generated 404.
#   H3 A 60s-period datapoint carries Unit == "Count" for all three metrics.
#   H4 CloudWatch publishes ALB metric minutes in order, so once the LATER window has landed the
#      EARLIER window's sums are final.
#   H5 AWS/ApplicationELB metrics are delivered well within the 600 s poll used here.
#   H6 The LoadBalancer dimension value is the last three ARN segments (app/<name>/<id>) and the
#      TargetGroup dimension value is targetgroup/<name>/<id>; each is derived from the resource id
#      after the last ":".

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alb-generated-responses-excluded-from-requestcount-and-target-codes"
GROUP = "metrics-and-alarms"
SERVICES = ["elbv2"]

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

_CIDR = "10.171.0.0/16"


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
    """Bounded retry. RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_GONE = {
    "InvalidVpcID.NotFound", "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
    "InvalidRouteTableID.NotFound", "InvalidSubnetID.NotFound", "InvalidAssociationID.NotFound",
    "InvalidGroup.NotFound", "ListenerNotFound", "RuleNotFound", "NoSuchEntity",
    "ResourceNotFoundException",
}


def _safe_cleanup(fn):
    """Teardown: done once the resource is gone; any other failure raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") not in _GONE:
                raise

    return _wrapped


def _http(ctx, url, *, method="GET", headers=None, timeout=20):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _own_public_vpc(ctx, cidr=_CIDR, n_subnets=2):
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs.

    Deliberately NOT the default VPC: a freshly provisioned sandbox account may not have one, and
    the resulting IndexError reads as an environment problem rather than a fidelity result.
    """
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    ]
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs, need {n_subnets} for a load balancer"
    )

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _safe_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _safe_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_safe_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{cidr.split('.')[0]}.{cidr.split('.')[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(_safe_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_safe_cleanup(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
    return vpc_id, subnet_ids


def _open_sg(ctx, vpc_id, ports=(80,)):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        # The load balancer's ENIs hold this group; _delete_net waits for them to be released.
        _safe_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))()

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
             "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
            for p in ports
        ],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(Name=name, Subnets=subnet_ids, Type="application",
                  Scheme="internal", Tags=list(_TAGS))
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
    assert lb["State"]["Code"] == "active", (
        f"load balancer state {lb['State']!r}, expected State.Code == 'active'"
    )
    return lb


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # A target group stays ResourceInUse until its listener rules are released.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop_tg)
    return tg


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(_safe_cleanup(lambda: elb.delete_listener(ListenerArn=arn)))
    return listener


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    )["Role"]["Arn"]

    def _drop_role():
        _safe_cleanup(lambda: iam.delete_role(RoleName=name))()

    ctx.on_cleanup(_drop_role)
    return arn


def _create_lambda(ctx, role_arn, source, *, timeout=20):
    """Create a function, absorbing only the documented role-propagation race.

    The retry loop is bounded and raises; it accepts ONLY InvalidParameterValueException, which is
    what Lambda returns while a freshly created role is not yet assumable.
    """
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=timeout, MemorySize=128,
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    arn = _poll_until(
        _try_create, lambda a: a is not None, timeout_s=180, interval_s=5,
        description=f"lambda {name} accepting the freshly created execution role",
    )
    ctx.on_cleanup(_safe_cleanup(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active", timeout_s=180, interval_s=3,
        description=f"lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": arn}


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


def _fixed(body, status="200", content_type="text/plain"):
    return [{"Type": "fixed-response", "FixedResponseConfig": {
        "StatusCode": status, "ContentType": content_type, "MessageBody": body}}]


def _path_rule(ctx, listener_arn, priority, path, actions):
    elb = ctx.client("elbv2")
    rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=priority,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": [path]}}],
        Actions=actions, Tags=list(_TAGS),
    ))["Rules"][0]
    ctx.on_cleanup(_safe_cleanup(lambda: elb.delete_rule(RuleArn=rule["RuleArn"])))
    return rule


def _wait_for_response(ctx, url, expected, *, timeout_s=300):
    """Poll until the load balancer serves exactly (status, body). Bounded; raises on timeout."""
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {type(exc).__name__}: {exc}>")
            return None
        seen.append(f"{status}:{body.strip()[:32]}")
        return (status, body.strip())

    return _poll_until(
        probe, lambda r: r == expected, timeout_s=timeout_s, interval_s=5,
        description=f"load balancer serving {expected!r} at {url} (observed: {seen[-8:]})",
    )


def _minute_floor(dt):
    return dt.replace(second=0, microsecond=0)


def _align_past_minute_boundary(margin_s=6):
    """Block until the wall clock is `margin_s` into a fresh UTC minute, and return that minute.

    Reason this wait exists: CloudWatch buckets ALB metrics into 60s periods keyed on the UTC
    minute. Two request batches that share a minute share a bucket, and the whole check is a
    comparison BETWEEN batches, so the batches must not share one. This is a computed alignment
    with a deadline, not a fixed sleep: it raises if the clock does not advance.
    """
    start_minute = _minute_floor(datetime.now(timezone.utc))
    deadline = time.monotonic() + 120

    def probe():
        now = datetime.now(timezone.utc)
        return (_minute_floor(now), now.second)

    while time.monotonic() < deadline:
        minute, second = probe()
        if minute > start_minute and second >= margin_s:
            return minute
        time.sleep(1)
    raise AssertionError(
        f"the UTC clock did not advance past {start_minute.isoformat()} + {margin_s}s within 120s"
    )
# ===== end helpers =====

#: 200 for any path ending /ok, 404 for any path ending /gone. Nothing else is reachable: every
#: other path is answered by the listener's fixed-response default action, so a stray internet
#: request to an internet-facing load balancer cannot contaminate the TARGET metrics this check
#: compares — it lands on the fixed response instead.
_FN_SRC = '''
def lambda_handler(event, context):
    path = (event.get("path") or "")
    if path.endswith("/gone"):
        return {"statusCode": 404, "statusDescription": "404 Not Found",
                "isBase64Encoded": False, "headers": {"Content-Type": "text/plain"},
                "body": "TARGET-404"}
    return {"statusCode": 200, "statusDescription": "200 OK",
            "isBase64Encoded": False, "headers": {"Content-Type": "text/plain"},
            "body": "TARGET-200"}
'''


def _metric_sum(ctx, metric, dimensions, start, end):
    """(sum, units) for one ALB metric over [start, end) at 60s granularity.

    Returns 0.0 with an empty unit set when CloudWatch has no datapoints, which is the honest
    representation of "not published" and is only ever compared against 0 on an absence leg.
    """
    cw = ctx.client("cloudwatch")
    resp = cw.get_metric_statistics(
        Namespace="AWS/ApplicationELB", MetricName=metric, Dimensions=list(dimensions),
        StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
    )
    points = resp["Datapoints"]
    return sum(p["Sum"] for p in points), {p.get("Unit") for p in points}


def _send(ctx, url, n, expected):
    """Send n requests and hard-assert every one of them got `expected` (status, body)."""
    for i in range(n):
        status, _hdrs, body = _http(ctx, url)
        assert (status, body.strip()) == expected, (
            f"request {i + 1}/{n} to {url} returned {(status, body.strip()[:80])!r}, expected "
            f"{expected!r}; the metric comparison below is only meaningful if every request in "
            f"the batch was served the same way"
        )


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html
@tags("axis:happy-path", "cap:c4", "concern:metrics", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """RequestCount counts only requests for which the ALB chose a target, and a 404 the ALB
    generated itself never lands in HTTPCode_Target_4XX_Count — the target-generated one does.
    """
    # Batch B (fixed-response default, no target), C (target 200) and D (target 404) land on
    # distinct UTC minutes; C and D are the delivery controls read before the absence legs on B.
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")

    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, ports=(80,))

    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda(ctx, role_arn, _FN_SRC)

    # Control: the artifact itself works, so a routing failure below cannot be blamed on it.
    direct = json.loads(lam.invoke(
        FunctionName=fn["name"], Payload=json.dumps({"path": "/x/ok"}).encode(),
    )["Payload"].read())
    assert direct.get("body") == "TARGET-200", (
        f"direct invoke of {fn['name']} returned {direct!r}, expected body 'TARGET-200'"
    )

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    lb_arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(ctx, lb_arn)

    tg = _create_target_group(ctx, TargetType="lambda")
    tg_arn = tg["TargetGroupArn"]
    _allow_elb_invoke(ctx, fn["name"], tg_arn)
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg_arn, Targets=[{"Id": fn["arn"]}]))

    listener = _create_listener(
        ctx, lb_arn, Port=80, Protocol="HTTP",
        DefaultActions=_fixed("ALB-FIXED-404", status="404"),
    )
    listener_arn = listener["ListenerArn"]
    slug = _clamp_name(ctx.unique_name("r"), 20)
    forward = [{"Type": "forward", "TargetGroupArn": tg_arn}]
    _path_rule(ctx, listener_arn, 10, f"/{slug}/ok", forward)
    _path_rule(ctx, listener_arn, 20, f"/{slug}/gone", forward)

    base = f"http://{lb['DNSName']}"
    fixed_url, ok_url, gone_url = f"{base}/", f"{base}/{slug}/ok", f"{base}/{slug}/gone"

    # H6 is asserted, not assumed: the dimension values are derived from the ARNs. The two ARN
    # shapes are NOT symmetric: a load balancer's resource id is "loadbalancer/app/<name>/<id>"
    # (the CloudWatch dimension drops the "loadbalancer/" type segment and keeps "app/<name>/<id>"),
    # but a target group's resource id is "targetgroup/<name>/<id>" with no extra type segment to
    # drop, so the CloudWatch dimension keeps the "targetgroup/" prefix as-is. A single
    # "last 3 slash-segments" rule happens to work for the load balancer (4 total segments) and
    # silently returns the WHOLE arn for the target group (3 total segments, so "last 3" is all of
    # them).
    lb_dim = [{"Name": "LoadBalancer", "Value": lb_arn.rsplit(":", 1)[-1].split("/", 1)[-1]}]
    tg_dim = [{"Name": "TargetGroup", "Value": tg_arn.rsplit(":", 1)[-1]},
              {"Name": "LoadBalancer", "Value": lb_dim[0]["Value"]}]
    assert lb_dim[0]["Value"].startswith("app/"), (
        f"LoadBalancer dimension derived from {lb_arn!r} is {lb_dim[0]['Value']!r}, expected it to "
        f"start with 'app/'"
    )
    assert tg_dim[0]["Value"].startswith("targetgroup/"), (
        f"TargetGroup dimension derived from {tg_arn!r} is {tg_dim[0]['Value']!r}, expected it to "
        f"start with 'targetgroup/'"
    )

    # Warm the data plane on all three routes before any batch, so batch minutes contain only the
    # batch. Each poll is bounded and raises.
    _wait_for_response(ctx, fixed_url, (404, "ALB-FIXED-404"))
    _wait_for_response(ctx, ok_url, (200, "TARGET-200"))
    _wait_for_response(ctx, gone_url, (404, "TARGET-404"))

    n_fixed, n_ok, n_gone = 25, 25, 15

    # --- batch B: the ALB answers, no target is chosen -------------------------------------
    b_start = _align_past_minute_boundary()
    _send(ctx, fixed_url, n_fixed, (404, "ALB-FIXED-404"))
    b_end = _minute_floor(datetime.now(timezone.utc)) + timedelta(minutes=1)

    # --- batch C: the target answers 200 ---------------------------------------------------
    c_start = _align_past_minute_boundary()
    _send(ctx, ok_url, n_ok, (200, "TARGET-200"))
    c_end = _minute_floor(datetime.now(timezone.utc)) + timedelta(minutes=1)

    # --- batch D: the target answers 404 ---------------------------------------------------
    d_start = _align_past_minute_boundary()
    _send(ctx, gone_url, n_gone, (404, "TARGET-404"))
    d_end = _minute_floor(datetime.now(timezone.utc)) + timedelta(minutes=1)

    # POSITIVE CONTROL for metric delivery on this wiring. Everything below is stated only after
    # this lands, which is what makes the absence claims about B a decision rather than a delay.
    rc_c, rc_units = _poll_until(
        lambda: _metric_sum(ctx, "RequestCount", lb_dim, c_start, c_end),
        lambda r: r[0] >= n_ok, timeout_s=600, interval_s=20,
        description=f"RequestCount reaching >= {n_ok} for the minute in which {n_ok} requests were "
                    f"forwarded to a target",
    )
    assert rc_units == {"Count"}, (
        f"RequestCount datapoints reported units {sorted(u or '<none>' for u in rc_units)!r}, "
        f"expected exactly {{'Count'}}"
    )

    t2xx_c, t2xx_units = _poll_until(
        lambda: _metric_sum(ctx, "HTTPCode_Target_2XX_Count", tg_dim, c_start, c_end),
        lambda r: r[0] >= n_ok, timeout_s=600, interval_s=20,
        description=f"HTTPCode_Target_2XX_Count reaching >= {n_ok} for the target group that "
                    f"served {n_ok} HTTP 200 responses",
    )
    assert t2xx_units == {"Count"}, (
        f"HTTPCode_Target_2XX_Count datapoints reported units "
        f"{sorted(u or '<none>' for u in t2xx_units)!r}, expected exactly {{'Count'}}"
    )

    # POSITIVE CONTROL for the target-4xx metric itself.
    t4xx_d, _ = _poll_until(
        lambda: _metric_sum(ctx, "HTTPCode_Target_4XX_Count", tg_dim, d_start, d_end),
        lambda r: r[0] >= n_gone, timeout_s=600, interval_s=20,
        description=f"HTTPCode_Target_4XX_Count reaching >= {n_gone} for the target group whose "
                    f"TARGET returned {n_gone} HTTP 404 responses",
    )

    # THE DISCRIMINATOR, leg 1: the fixed-response minute chose no target, so RequestCount for it
    # is zero. Read AFTER the later minutes landed, so a slow publisher cannot score here.
    rc_b, _ = _metric_sum(ctx, "RequestCount", lb_dim, b_start, b_end)
    assert rc_b == 0.0, (
        f"RequestCount over {b_start.isoformat()}..{b_end.isoformat()} was {rc_b}, expected 0: all "
        f"{n_fixed} requests in that minute were answered by a fixed-response action, so the load "
        f"balancer never chose a target (control: the target minute measured {rc_c})"
    )

    # THE DISCRIMINATOR, leg 2: an ALB-generated 404 is not a TARGET 4xx.
    t4xx_b, _ = _metric_sum(ctx, "HTTPCode_Target_4XX_Count", tg_dim, b_start, b_end)
    assert t4xx_b == 0.0, (
        f"HTTPCode_Target_4XX_Count over {b_start.isoformat()}..{b_end.isoformat()} was {t4xx_b}, "
        f"expected 0: those {n_fixed} 404s were generated by the load balancer, not by the target "
        f"(control: the target-404 minute measured {t4xx_d})"
    )

    # And no target 2xx in the fixed-response minute either — the target was never invoked.
    t2xx_b, _ = _metric_sum(ctx, "HTTPCode_Target_2XX_Count", tg_dim, b_start, b_end)
    assert t2xx_b == 0.0, (
        f"HTTPCode_Target_2XX_Count over {b_start.isoformat()}..{b_end.isoformat()} was {t2xx_b}, "
        f"expected 0 (control: the target-200 minute measured {t2xx_c})"
    )

    # Two consecutive identical reads of the settled B minute: a target that lazily materialises a
    # metric on read would move here.
    rc_b_again, _ = _metric_sum(ctx, "RequestCount", lb_dim, b_start, b_end)
    t4xx_b_again, _ = _metric_sum(ctx, "HTTPCode_Target_4XX_Count", tg_dim, b_start, b_end)
    assert (rc_b_again, t4xx_b_again) == (rc_b, t4xx_b), (
        f"re-reading the settled minute {b_start.isoformat()} returned "
        f"RequestCount={rc_b_again} HTTPCode_Target_4XX_Count={t4xx_b_again}, expected the "
        f"unchanged {rc_b}/{t4xx_b} — a metric read must not advance metric state"
    )


# Network teardown: load balancers and similar resources delete asynchronously and leave ENIs in
# the subnet or security group, so an immediate delete fails with DependencyViolation. Wait for
# the ENIs (bounded, shared by all of one check's network deletes), then retry within the window.
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
