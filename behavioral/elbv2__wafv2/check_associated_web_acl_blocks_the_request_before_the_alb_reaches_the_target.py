"""associated-web-acl-blocks-the-request-before-the-alb-reaches-the-target."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associated-web-acl-blocks-the-request-before-the-alb-reaches-the-target"
GROUP = "cross-service"
SERVICES = ["elbv2", "wafv2"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException", "WAFOptimisticLockException",
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

_CIDR = "10.178.0.0/16"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


def _retry_throttled(fn, attempts=6, extra_codes=frozenset()):
    delays = [3, 6, 12, 24, 30, 30]
    last = None
    codes = _THROTTLE_CODES | extra_codes
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes:
                raise
            last = exc
            time.sleep(delays[min(i, len(delays) - 1)])
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition", ctx=None):
    """Bounded retry. RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_GONE_CODES = ("Gateway.NotAttached", "NoSuchEntity", "ResourceNotFoundException", "ListenerNotFound",
               "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist", "WAFNonexistentItemException")


def _safe_cleanup(fn):
    """Teardown-only tolerance of an already-gone resource. Never used on an assertion path."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if not (code.endswith(".NotFound") or code in _GONE_CODES):
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
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs."""
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

    octets = cidr.split(".")
    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
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
        last = None
        for _ in range(40):
            try:
                _delete_net(ec2, "delete_security_group", GroupId=sg_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidGroup.NotFound":
                    return
                last = exc
                time.sleep(3)
        raise RuntimeError(f"security group {sg_id} was not deleted: {last!r}")

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
        last = None
        for _ in range(90):
            try:
                last = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)
        raise RuntimeError(f"load balancer {arn} was not deleted: {last!r}")

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=_budget_s(ctx, timeout_s), interval_s=1, ctx=ctx,
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
        last = None
        for _ in range(10):
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "TargetGroupNotFound":
                    return
                last = exc
                time.sleep(4)
        raise RuntimeError(f"target group {arn} was not deleted: {last!r}")

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


def _create_queue(ctx):
    """The side channel: exact invocation counts the ALB and WAF APIs will not report."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"),
        tags={t["Key"]: t["Value"] for t in _TAGS},
    )["QueueUrl"]
    ctx.on_cleanup(_safe_cleanup(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _drain(ctx, queue_url, *, settle_s=3):
    """Empty the queue and return the message bodies removed. Bounded by a deadline.

    SQS receives are a sample, so `settle_s` sets how many consecutive empty 1 s long-polls mean empty.
    """
    sqs = ctx.client("sqs")
    drained = []
    empties = 0
    needed_empties = max(2, settle_s)
    deadline = time.monotonic() + _budget_s(ctx, 60)
    while time.monotonic() < deadline and empties < needed_empties:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=60)
        msgs = got.get("Messages") or []
        if not msgs:
            empties += 1
            continue
        empties = 0
        for m in msgs:
            drained.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    if empties < needed_empties and _budget_spent(ctx):
        raise TimeoutError("draining the side-channel queue: the run budget ended first; not graded")
    return drained


def _collect(ctx, queue_url, *, want, timeout_s):
    """Receive until `want` messages arrive, or raise. Returns (bodies, elapsed_seconds)."""
    sqs = ctx.client("sqs")
    bodies = []
    start = time.monotonic()
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = start + timeout_s
    while time.monotonic() < deadline and len(bodies) < want:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2, VisibilityTimeout=60)
        for m in got.get("Messages") or []:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    elapsed = time.monotonic() - start
    if len(bodies) < want and _budget_spent(ctx):
        raise TimeoutError(f"{want} side-channel invocation(s): the run budget ended first; not graded")
    assert len(bodies) >= want, (
        f"the target reported {len(bodies)} invocation(s) on the side channel within {timeout_s}s, "
        f"expected {want}; bodies={bodies!r}"
    )
    return bodies, elapsed


def _visible_count(ctx, queue_url):
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (int(attrs["ApproximateNumberOfMessages"]),
            int(attrs["ApproximateNumberOfMessagesNotVisible"]))


def _create_lambda_role(ctx, queue_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    )["Role"]["Arn"]

    def _drop_role():
        _safe_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sqs"))()
        _safe_cleanup(lambda: iam.delete_role(RoleName=name))()

    ctx.on_cleanup(_drop_role)
    iam.put_role_policy(
        RoleName=name, PolicyName="sqs",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage",
                           "Resource": queue_arn}],
        }),
    )
    return arn


def _create_lambda(ctx, role_arn, source, env):
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
                Code={"ZipFile": buf.getvalue()}, Timeout=20, MemorySize=256,
                Environment={"Variables": env},
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    arn = _poll_until(
        _try_create, lambda a: a is not None, timeout_s=_budget_s(ctx, 180), interval_s=2, ctx=ctx,
        description=f"lambda {name} accepting the freshly created execution role",
    )
    ctx.on_cleanup(_safe_cleanup(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active", timeout_s=_budget_s(ctx, 180), interval_s=1, ctx=ctx,
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


def _create_web_acl(ctx, blocked_ua):
    """A REGIONAL WebACL whose ONE rule blocks a single, unique User-Agent."""
    waf = ctx.client("wafv2")
    name = _clamp_name(ctx.unique_name("sim2realacl"), 40)
    created = _retry_throttled(lambda: waf.create_web_acl(
        Name=name, Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        Description="sim2real elbv2 x wafv2 enforcement check",
        Rules=[{
            "Name": "block-marker-ua",
            "Priority": 0,
            "Statement": {"ByteMatchStatement": {
                "SearchString": blocked_ua.encode(),
                "FieldToMatch": {"SingleHeader": {"Name": "user-agent"}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "EXACTLY",
            }},
            "Action": {"Block": {}},
            "VisibilityConfig": {"SampledRequestsEnabled": True,
                                 "CloudWatchMetricsEnabled": True,
                                 "MetricName": "sim2realBlockMarkerUa"},
        }],
        VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                          "MetricName": _clamp_name(name, 40)},
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    ))["Summary"]

    def _drop_acl():
        last = None
        for _ in range(40):
            try:
                current = waf.get_web_acl(Name=name, Scope="REGIONAL", Id=created["Id"])
                waf.delete_web_acl(Name=name, Scope="REGIONAL", Id=created["Id"],
                                   LockToken=current["LockToken"])
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "WAFNonexistentItemException":
                    return
                # WAFAssociatedItemException while the ALB association is still tearing down.
                last = exc
                time.sleep(3)
        raise RuntimeError(f"web ACL {name} was not deleted: {last!r}")

    ctx.on_cleanup(_drop_acl)
    return {"name": name, "id": created["Id"], "arn": created["ARN"]}


def _acl_for_resource(ctx, lb_arn):
    waf = ctx.client("wafv2")
    return (waf.get_web_acl_for_resource(ResourceArn=lb_arn).get("WebACL") or {}).get("ARN")


def _probe(ctx, url, ua):
    try:
        status, _hdrs, body = _http(ctx, url, headers={"User-Agent": ua})
    except (urllib.error.URLError, OSError) as exc:
        return (None, f"<transport: {type(exc).__name__}: {exc}>")
    return (status, body.strip())

#: The Lambda target reports each request on the side channel before responding. Internet
#: scanners probe a public ALB within minutes and are rightly let through, so only this run's
#: probe path is reported.
_FN_SRC = '''
import json
import os

import boto3

_SQS = boto3.client("sqs")
_QUEUE = os.environ["QUEUE_URL"]
_EXPECT_PATH = os.environ["EXPECT_PATH"]


def lambda_handler(event, context):
    headers = event.get("headers") or {}
    if event.get("path") == _EXPECT_PATH:
        _SQS.send_message(
            QueueUrl=_QUEUE,
            MessageBody=json.dumps({
                "path": event.get("path"),
                "user_agent": headers.get("user-agent"),
                "request_id": context.aws_request_id,
            }),
        )
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": {"Content-Type": "text/plain"}, "body": "TARGET-REACHED"}
'''


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A WebACL associated with an ALB answers a matching User-Agent with 403 and the target is never
    invoked while a non-matching request is served; disassociating restores the blocked request.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/waf-application-load-balancer.html
    """
    elb = ctx.client("elbv2")
    waf = ctx.client("wafv2")

    marker = _clamp_name(ctx.unique_name("mk"), 20)
    expect_path = f"/{marker}/probe"
    blocked_ua = f"sim2real-blocked/{marker}"
    allowed_ua = f"sim2real-allowed/{marker}"

    queue_url, queue_arn = _create_queue(ctx)
    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, ports=(80,))

    role_arn = _create_lambda_role(ctx, queue_arn)
    fn = _create_lambda(
        ctx, role_arn, _FN_SRC, {"QUEUE_URL": queue_url, "EXPECT_PATH": expect_path})

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    lb_arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(ctx, lb_arn)

    tg = _create_target_group(ctx, TargetType="lambda")
    tg_arn = tg["TargetGroupArn"]
    _allow_elb_invoke(ctx, fn["name"], tg_arn)
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg_arn, Targets=[{"Id": fn["arn"]}]))
    _create_listener(
        ctx, lb_arn, Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])

    url = f"http://{lb['DNSName']}{expect_path}"

    # No WebACL: both User-Agents reach the target.
    pre_existing = _acl_for_resource(ctx, lb_arn)
    assert pre_existing is None, (
        f"GetWebACLForResource already reports a WebACL ({pre_existing!r}) on the load balancer this "
        f"check just created; the association legs below would then prove nothing"
    )
    warm = _poll_until(
        lambda: _probe(ctx, url, blocked_ua), lambda r: r == (200, "TARGET-REACHED"),
        timeout_s=_budget_s(ctx, 420), interval_s=2, ctx=ctx,
        description="the ALB forwarding to the Lambda target before any WebACL exists",
    )
    assert warm == (200, "TARGET-REACHED"), f"warm-up returned {warm!r}, expected (200, ...)"
    _drain(ctx, queue_url)

    for ua in (blocked_ua, allowed_ua):
        got = _probe(ctx, url, ua)
        assert got == (200, "TARGET-REACHED"), (
            f"with no WebACL, User-Agent {ua!r} got {got!r}, expected (200, 'TARGET-REACHED')"
        )
    baseline, _ = _collect(ctx, queue_url, want=2, timeout_s=120)
    seen_uas = {json.loads(b)["user_agent"] for b in baseline}
    assert seen_uas == {blocked_ua, allowed_ua}, (
        f"the side channel recorded User-Agents {sorted(seen_uas)!r}, expected both "
        f"{sorted([blocked_ua, allowed_ua])!r} — the target must see the header the client sent"
    )
    _drain(ctx, queue_url)

    # Break exactly one thing: associate the WebACL.
    acl = _create_web_acl(ctx, blocked_ua)
    # AssociateWebACL on a just-activated ALB can answer WAFUnavailableEntityException for up to
    # ~2 minutes; AWS's guidance for that error is to retry.
    _retry_throttled(
        lambda: waf.associate_web_acl(WebACLArn=acl["arn"], ResourceArn=lb_arn),
        attempts=10, extra_codes=frozenset({"WAFUnavailableEntityException"}),
    )
    ctx.on_cleanup(_safe_cleanup(lambda: waf.disassociate_web_acl(ResourceArn=lb_arn)))

    associated = _poll_until(
        lambda: _acl_for_resource(ctx, lb_arn), lambda a: a == acl["arn"],
        timeout_s=_budget_s(ctx, 180), interval_s=1, ctx=ctx,
        description=f"GetWebACLForResource reporting {acl['arn']!r} on the load balancer",
    )
    assert associated == acl["arn"], (
        f"GetWebACLForResource reports {associated!r}, expected {acl['arn']!r}"
    )

    blocked = _poll_until(
        lambda: _probe(ctx, url, blocked_ua), lambda r: r[0] == 403,
        timeout_s=_budget_s(ctx, 300), interval_s=2, ctx=ctx,
        description=f"the WebACL starting to refuse User-Agent {blocked_ua!r} with 403",
    )
    # Anything the convergence poll leaked onto the side channel belongs to the transition.
    _drain(ctx, queue_url)
    assert blocked[0] == 403, (
        f"the blocked User-Agent got HTTP {blocked[0]} (body {blocked[1][:120]!r}), expected 403"
    )
    assert blocked[1] != "TARGET-REACHED", (
        f"the 403 response body was the TARGET's body {blocked[1][:60]!r}; a WAF block must be "
        f"generated at the load balancer, not proxied from the target"
    )

    # Same-instant positive control: the other User-Agent still gets through.
    allowed = _probe(ctx, url, allowed_ua)
    assert allowed == (200, "TARGET-REACHED"), (
        f"with the WebACL associated, the NON-matching User-Agent {allowed_ua!r} got {allowed!r}, "
        f"expected (200, 'TARGET-REACHED') — without this the 403 above is indistinguishable from "
        f"'the WebACL blocks everything'"
    )
    control_msgs, _ = _collect(ctx, queue_url, want=1, timeout_s=120)
    assert json.loads(control_msgs[0])["user_agent"] == allowed_ua, (
        f"the side channel recorded {control_msgs[0]!r} for the allowed request, expected "
        f"user_agent {allowed_ua!r}"
    )
    _drain(ctx, queue_url)

    # Effect absent: blocked requests never reach the target. A non-matching request sent after
    # them is the positive control: once its invocation is on the side channel, so is any
    # invocation the blocked requests caused.
    for i in range(3):
        got = _probe(ctx, url, blocked_ua)
        assert got[0] == 403, (
            f"blocked request {i + 1}/3 got HTTP {got[0]} (body {got[1][:80]!r}), expected 403"
        )
    after = _probe(ctx, url, allowed_ua)
    assert after == (200, "TARGET-REACHED"), (
        f"the NON-matching User-Agent {allowed_ua!r} sent after the blocked requests got {after!r}, "
        f"expected (200, 'TARGET-REACHED')"
    )
    seen, _ = _collect(ctx, queue_url, want=1, timeout_s=120)
    seen += _drain(ctx, queue_url)
    leaked = [b for b in seen if json.loads(b)["user_agent"] != allowed_ua]
    assert leaked == [], (
        f"the target was invoked {len(leaked)} time(s) by requests WAF answered with 403: "
        f"{leaked!r}; expected zero before the allowed request sent after them was invoked"
    )
    visible, in_flight = _visible_count(ctx, queue_url)
    assert (visible, in_flight) == (0, 0), (
        f"a second independent observable disagrees: ApproximateNumberOfMessages={visible}, "
        f"ApproximateNumberOfMessagesNotVisible={in_flight}, expected (0, 0)"
    )

    # Restore the one thing that changed.
    _retry_throttled(lambda: waf.disassociate_web_acl(ResourceArn=lb_arn))
    _poll_until(
        lambda: _acl_for_resource(ctx, lb_arn), lambda a: a is None,
        timeout_s=_budget_s(ctx, 180), interval_s=1, ctx=ctx,
        description="GetWebACLForResource reporting no WebACL after DisassociateWebACL",
    )
    restored = _poll_until(
        lambda: _probe(ctx, url, blocked_ua), lambda r: r == (200, "TARGET-REACHED"),
        timeout_s=_budget_s(ctx, 300), interval_s=2, ctx=ctx,
        description=f"the identical request with User-Agent {blocked_ua!r} being served again once "
                    f"the WebACL is disassociated",
    )
    assert restored == (200, "TARGET-REACHED"), (
        f"after disassociating the WebACL the identical blocked request returned {restored!r}, "
        f"expected (200, 'TARGET-REACHED') — so the 403 was attributable to the association alone"
    )
    final_msgs, _ = _collect(ctx, queue_url, want=1, timeout_s=120)
    assert json.loads(final_msgs[0])["user_agent"] == blocked_ua, (
        f"the side channel recorded {final_msgs[0]!r} after the WebACL was removed, expected "
        f"user_agent {blocked_ua!r}"
    )


# Resources in this VPC delete asynchronously and leave ENIs behind for a while, so an immediate
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for
# the ENIs to go, retry DependencyViolation in the same window, then fail naming the ENIs left.
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
        _time.sleep(3)
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
        _time.sleep(3)


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
