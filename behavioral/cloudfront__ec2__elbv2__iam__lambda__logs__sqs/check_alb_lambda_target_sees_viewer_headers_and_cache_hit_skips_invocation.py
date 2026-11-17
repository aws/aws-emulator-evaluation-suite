"""alb-lambda-target-sees-viewer-headers-and-cache-hit-skips-invocation."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alb-lambda-target-sees-viewer-headers-and-cache-hit-skips-invocation"
GROUP = "cross-service"
SERVICES = ["cloudfront", "ec2", "elbv2", "iam", "lambda", "logs", "sqs"]

#: CloudFront's control plane is global and signed in us-east-1; the VPC, ALB and function are regional.
CLOUDFRONT_REGION = "us-east-1"

#: The managed origin request policy "AllViewer" forwards no CloudFront-generated header, so a custom
#: one is built instead: CloudFront-Viewer-* headers are added only when the policy names them
#: explicitly, even alongside "all viewer headers".
_CLOUDFRONT_VIEWER_ADDRESS = "CloudFront-Viewer-Address"
_CLOUDFRONT_VIEWER_COUNTRY = "CloudFront-Viewer-Country"

SECRET_HEADER = "X-Origin-Secret"
DENIED_BODY = "sim2real-direct-request-denied"
_TAG_KEY, _TAG_VALUE = "sim2real", "xsvc-cloudfront-alb-lambda"
_TAG = {"Key": _TAG_KEY, "Value": _TAG_VALUE}

_IPV4 = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
_XFF_RE = re.compile(rf"^{_IPV4}(,\s*{_IPV4})*$")
_VIEWER_ADDRESS_RE = re.compile(r"^[0-9a-fA-F.:]+:\d+$")
_VIEWER_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _tagspec(kind, name):
    return [{"ResourceType": kind, "Tags": [_TAG, {"Key": "Name", "Value": name}]}]


def _clamp(name, maxlen=32):
    return name[:maxlen].rstrip("-")


def _teardown_vpc(ec2, vpc_id, *, budget_s=600.0) -> None:
    """Delete everything this check put in its own VPC, then the VPC; registered first, runs LAST.

    A lingering ALB ENI can hold the security group and subnets (DependencyViolation), so each
    delete retries only that code inside a shared budget; a VPC that never converges raises.
    """
    deadline = time.monotonic() + budget_s

    def retry(fn):
        while True:
            try:
                return fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code.endswith("NotFound"):
                    return None
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    raise
                time.sleep(3)

    filt = [{"Name": "vpc-id", "Values": [vpc_id]}]
    for sg in ec2.describe_security_groups(Filters=filt)["SecurityGroups"]:
        if sg["GroupName"] != "default":
            retry(lambda g=sg["GroupId"]: ec2.delete_security_group(GroupId=g))
    for sn in ec2.describe_subnets(Filters=filt)["Subnets"]:
        retry(lambda s=sn["SubnetId"]: ec2.delete_subnet(SubnetId=s))
    for rt in ec2.describe_route_tables(Filters=filt)["RouteTables"]:
        if not any(a.get("Main") for a in rt.get("Associations", [])):
            retry(lambda r=rt["RouteTableId"]: ec2.delete_route_table(RouteTableId=r))
    for igw in ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]:
        retry(lambda i=igw["InternetGatewayId"]: ec2.detach_internet_gateway(
            InternetGatewayId=i, VpcId=vpc_id))
        retry(lambda i=igw["InternetGatewayId"]: ec2.delete_internet_gateway(InternetGatewayId=i))
    retry(lambda: ec2.delete_vpc(VpcId=vpc_id))


def _public_vpc_and_sg(ctx, ec2, name):
    """A self-owned VPC with two public subnets and a security group for the ALB's listener port."""
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"an ALB needs two available AZs in {ctx.region}, found {zones!r}"

    vpc_id = ec2.create_vpc(CidrBlock="10.61.0.0/16",
                            TagSpecifications=_tagspec("vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown_vpc(ctx.client("ec2"), vpc_id))
    igw = ec2.create_internet_gateway(
        TagSpecifications=_tagspec("internet-gateway", name))["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    rt = ec2.create_route_table(VpcId=vpc_id,
                                TagSpecifications=_tagspec("route-table", name))["RouteTable"]
    ec2.create_route(RouteTableId=rt["RouteTableId"], DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    subnets = []
    for i, az in enumerate(zones[:2]):
        sn = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.61.{i + 1}.0/24", AvailabilityZone=az,
                               TagSpecifications=_tagspec("subnet", name))["Subnet"]["SubnetId"]
        ec2.associate_route_table(RouteTableId=rt["RouteTableId"], SubnetId=sn)
        subnets.append(sn)

    # The ALB admits CloudFront's own origin-facing ranges (so the edge can reach it) and this
    # check's own runner (so the direct-request control below can reach it too); nothing else.
    origin_facing = ec2.describe_managed_prefix_lists(Filters=[{
        "Name": "prefix-list-name", "Values": ["com.amazonaws.global.cloudfront.origin-facing"],
    }])["PrefixLists"][0]["PrefixListId"]
    sg = ec2.create_security_group(GroupName=name, Description="sim2real alb http only", VpcId=vpc_id,
                                   TagSpecifications=_tagspec("security-group", name))["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
         "PrefixListIds": [{"PrefixListId": origin_facing}]},
        *({"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": cidr}]}
          for cidr in ctx.ingress_cidrs()),
    ])
    return vpc_id, subnets, sg


def _create_queue(ctx):
    """The side channel: proves how many times the function ran, independent of the HTTP answer."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-q-"),
                           tags={_TAG_KEY: _TAG_VALUE})["QueueUrl"]

    def _drop_queue():
        try:
            sqs.delete_queue(QueueUrl=url)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
                raise

    ctx.on_cleanup(_drop_queue)
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_new(ctx, queue_url, *, window_s):
    """Everything that arrives on ``queue_url`` over ``window_s``, deleted as it is read."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + window_s
    bodies = []
    while True:
        remaining = max(0, deadline - time.monotonic())
        got = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                  WaitTimeSeconds=min(5, int(remaining)) if remaining > 1 else 0,
                                  VisibilityTimeout=30)
        for m in got.get("Messages") or []:
            bodies.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if time.monotonic() >= deadline:
            return bodies


def _create_lambda_role(ctx, iam, queue_arn):
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]})
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust, Tags=[_TAG])["Role"]["Arn"]

    def _drop_role():
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="sqs-send")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_drop_role)
    iam.put_role_policy(RoleName=name, PolicyName="sqs-send", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    }))
    return arn


def _reap_log_group_loop(ctx, logs, fn_name):
    """Registered BEFORE create_function so LIFO runs it AFTER the delete: a buffered flush can
    recreate ``/aws/lambda/<fn>`` after one delete, so this re-deletes over a few rounds."""
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


#: The handler echoes the headers the ALB handed it, the request path and a fresh id per
#: invocation, to both the HTTP response and an SQS side channel, so a caller can tell whether it
#: ran without trusting the HTTP response alone.
#: NOTE: this source runs inside AWS Lambda, not in the check process that builds the deployment zip.
_FN_SRC = '''
import json
import os
import uuid

import boto3

_SQS = boto3.client("sqs")
_QUEUE = os.environ["QUEUE_URL"]
_WANTED = ("x-forwarded-for", "host", "cloudfront-viewer-address", "cloudfront-viewer-country")


def lambda_handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    invocation_id = str(uuid.uuid4())
    captured = {name: headers.get(name) for name in _WANTED}
    payload = json.dumps({"invocation_id": invocation_id, "path": event.get("path"),
                          "headers": captured})
    _SQS.send_message(QueueUrl=_QUEUE, MessageBody=payload)
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": {"Content-Type": "application/json"}, "body": payload}
'''


def _create_lambda(ctx, lam, logs, role_arn, queue_url):
    name = ctx.unique_name("sim2real-xsvc-fn-")
    _reap_log_group_loop(ctx, logs, name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _FN_SRC)

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler", Code={"ZipFile": buf.getvalue()},
                Timeout=15, MemorySize=256, Environment={"Variables": {"QUEUE_URL": queue_url}},
                Tags={_TAG_KEY: _TAG_VALUE})["FunctionArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None  # IAM propagation of the freshly created execution role only.
            raise

    arn = _poll_until(_try_create, lambda a: a is not None, timeout_s=180, interval_s=5,
                      description=f"lambda {name} accepting the freshly created execution role")

    def _drop_fn():
        try:
            lam.delete_function(FunctionName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_drop_fn)
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name).get("State"),
                lambda s: s == "Active", timeout_s=180, interval_s=3,
                description=f"lambda {name} reaching State=Active")
    return name, arn


def _delete_load_balancer(elb, lb_arn):
    try:
        elb.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        return
    elb.get_waiter("load_balancers_deleted").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _delete_target_group(elb, tg_arn, *, timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elb.delete_target_group(TargetGroupArn=tg_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _delete_distribution(cf, dist_id, *, timeout_s=1200.0):
    """Disable the distribution, wait until the change is Deployed, then delete it."""
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    _poll_until(lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
                lambda st: st == "Deployed", timeout_s=timeout_s, interval_s=20.0,
                description=f"disabled distribution {dist_id} to reach Deployed")
    cf.delete_distribution(Id=dist_id, IfMatch=cf.get_distribution(Id=dist_id)["ETag"])


def _get(ctx, session, url):
    """One GET through ``ctx.endpoint_route``; a transport error is returned, not raised."""
    try:
        target, route = ctx.endpoint_route(url)
        return session.get(target, timeout=20, headers=route, verify=ctx.http_verify)
    except requests.RequestException as exc:  # transport only (DNS / provisioning)
        return exc


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A distribution forwards X-Forwarded-For and the explicitly listed CloudFront-Viewer-* headers to
    an ALB Lambda target; a repeated request is served from the cache without a new invocation, and
    a request straight at the ALB with no secret header gets the listener's fixed 403 unserved.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-xsvc-")
    secret = ctx.unique_name("sim2real-secret-")
    marker = ctx.unique_name("m")

    vpc_id, subnets, sg = _public_vpc_and_sg(ctx, ec2, name)
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx, iam, queue_arn)
    fn_name, fn_arn = _create_lambda(ctx, lam, logs, role_arn, queue_url)

    lb = elb.create_load_balancer(Name=_clamp(name), Subnets=subnets, SecurityGroups=[sg],
                                  Scheme="internet-facing", Type="application", IpAddressType="ipv4",
                                  Tags=[_TAG])["LoadBalancers"][0]
    lb_arn, alb_dns = lb["LoadBalancerArn"], lb["DNSName"]
    ctx.on_cleanup(lambda: _delete_load_balancer(ctx.client("elbv2"), lb_arn))

    tg = elb.create_target_group(Name=_clamp(ctx.unique_name("sim2real-xsvc-tg-")),
                                 TargetType="lambda", Tags=[_TAG])["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group(ctx.client("elbv2"), tg_arn))

    lam.add_permission(FunctionName=fn_name, StatementId="sim2real-alb-invoke",
                       Action="lambda:InvokeFunction", Principal="elasticloadbalancing.amazonaws.com",
                       SourceArn=tg_arn, SourceAccount=ctx.account)
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=fn_name,
                                                 StatementId="sim2real-alb-invoke"))

    elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])
    ctx.on_cleanup(lambda: elb.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}]))

    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "403", "ContentType": "text/plain", "MessageBody": DENIED_BODY}}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=listener_arn))
    elb.create_rule(
        ListenerArn=listener_arn, Priority=1,
        Conditions=[{"Field": "http-header", "HttpHeaderConfig": {
            "HttpHeaderName": SECRET_HEADER, "Values": [secret]}}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )

    orp_resp = cf.create_origin_request_policy(OriginRequestPolicyConfig={
        "Name": ctx.unique_name("sim2real-xsvc-orp-"),
        "Comment": "forwards viewer headers and the CloudFront viewer-location headers",
        "HeadersConfig": {"HeaderBehavior": "allViewerAndWhitelistCloudFront", "Headers": {
            "Quantity": 2, "Items": [_CLOUDFRONT_VIEWER_ADDRESS, _CLOUDFRONT_VIEWER_COUNTRY]}},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    })
    orp_id, orp_etag = orp_resp["OriginRequestPolicy"]["Id"], orp_resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_origin_request_policy(Id=orp_id, IfMatch=orp_etag))

    cp_resp = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cp-"),
        "Comment": "a static cache key so an identical path is a repeatable cache hit",
        "DefaultTTL": 60, "MaxTTL": 60, "MinTTL": 0,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False, "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })
    cp_id, cp_etag = cp_resp["CachePolicy"]["Id"], cp_resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_cache_policy(Id=cp_id, IfMatch=cp_etag))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-xsvc-cr-"),
        "Comment": "alb lambda origin with a secret header and a cacheable response",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "alb",
            "DomainName": alb_dns,
            "CustomHeaders": {"Quantity": 1, "Items": [
                {"HeaderName": SECRET_HEADER, "HeaderValue": secret}]},
            "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443,
                                   "OriginProtocolPolicy": "http-only"},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "alb",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": cp_id,
            "OriginRequestPolicyId": orp_id,
        },
    })["Distribution"]
    dist_id, dist_domain = dist["Id"], dist["DomainName"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))

    _poll_until(lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
                ["LoadBalancers"][0]["State"]["Code"],
                lambda s: s == "active", timeout_s=600.0, interval_s=10.0,
                description=f"ALB {name} to become active")
    _poll_until(lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
                lambda s: s == "Deployed", timeout_s=1200.0, interval_s=15.0,
                description=f"distribution {dist_id} to reach Deployed")

    session = requests.Session()
    session.trust_env = False

    # ---- warm-up: the edge domain needs a moment to resolve after the distribution deploys. -----
    _poll_until(lambda: _get(ctx, session, f"{dist_domain}/sim2real/warmup"),
                lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                timeout_s=300.0, interval_s=10.0, description="200 through the distribution")
    _receive_new(ctx, queue_url, window_s=1)  # drain whatever the warm-up invoked; not graded.

    # ---- BEAT 1: a fresh path's first edge request reaches the function through the origin. -----
    path = f"/sim2real/{marker}"
    first = _get(ctx, session, f"{dist_domain}{path}")
    assert isinstance(first, requests.Response) and first.status_code == 200, (
        f"the first request to {path} must reach the function through the edge, got {first!r}")
    assert first.headers.get("X-Cache") == "Miss from cloudfront", (
        f"a never-requested path's first response must be a cache miss, X-Cache was "
        f"{first.headers.get('X-Cache')!r}")
    first_body = json.loads(first.text)
    first_headers = first_body["headers"]
    assert first_body["path"] == path, (
        f"the function saw path {first_body['path']!r}, expected the requested {path!r}")
    assert first_headers["host"] == dist_domain, (
        f"forwarding all viewer headers must carry the viewer's own Host (the distribution's "
        f"domain) to the origin unchanged, got {first_headers['host']!r}, expected {dist_domain!r}")
    assert first_headers["x-forwarded-for"] and _XFF_RE.match(first_headers["x-forwarded-for"]), (
        f"the ALB must add an X-Forwarded-For header to every Lambda-target invocation, got "
        f"{first_headers['x-forwarded-for']!r}")
    assert first_headers["cloudfront-viewer-address"] and _VIEWER_ADDRESS_RE.match(
        first_headers["cloudfront-viewer-address"]), (
        f"the listed CloudFront-Viewer-Address header must reach the origin as 'ip:port', "
        f"got {first_headers['cloudfront-viewer-address']!r}")
    assert first_headers["cloudfront-viewer-country"] and _VIEWER_COUNTRY_RE.match(
        first_headers["cloudfront-viewer-country"]), (
        f"the listed CloudFront-Viewer-Country header must reach the origin as a two-letter "
        f"code, got {first_headers['cloudfront-viewer-country']!r}")

    sent_at = time.monotonic()
    first_delivery = _poll_until(
        lambda: _receive_new(ctx, queue_url, window_s=2),
        lambda bodies: any(b["invocation_id"] == first_body["invocation_id"] for b in bodies),
        timeout_s=60.0, interval_s=1.0, description="the side channel reporting the first invocation")
    latency_s = time.monotonic() - sent_at
    assert any(b["invocation_id"] == first_body["invocation_id"] for b in first_delivery), (
        f"the side channel never reported invocation {first_body['invocation_id']!r}: "
        f"{first_delivery!r}")

    # ---- BEAT 2: an identical second request is served from the cache, with no new invocation. --
    second = _get(ctx, session, f"{dist_domain}{path}")
    assert isinstance(second, requests.Response) and second.status_code == 200, (
        f"the second identical request to {path} must also succeed, got {second!r}")
    assert second.headers.get("X-Cache") == "Hit from cloudfront", (
        f"the second identical request must be a cache hit, X-Cache was "
        f"{second.headers.get('X-Cache')!r}")
    assert second.text == first.text, (
        f"a cache hit must return the exact first response body, got {second.text[:300]!r}, "
        f"expected {first.text[:300]!r}")

    # Only invocations for this path count: a late warm-up delivery is not one of them.
    window_s = max(10.0, 3.0 * latency_s)
    after_hit = [b for b in _receive_new(ctx, queue_url, window_s=window_s) if b["path"] == path]
    assert after_hit == [], (
        f"a cache hit must not invoke the function again; the side channel reported "
        f"{after_hit!r} within {window_s:.1f}s of the hit")

    # ---- BEAT 3 (control): straight at the ALB with no secret header, the listener denies it ----
    # ---- before the target group, let alone the function, is ever reached. ------------------
    direct = _get(ctx, session, f"http://{alb_dns}{path}")
    assert isinstance(direct, requests.Response), f"the ALB {alb_dns} must answer directly: {direct!r}"
    assert (direct.status_code, direct.text) == (403, DENIED_BODY), (
        f"a direct request with no {SECRET_HEADER} must get the listener's fixed 403, got "
        f"{(direct.status_code, direct.text[:200])!r}")
    direct_window = [
        b for b in _receive_new(ctx, queue_url, window_s=window_s) if b["path"] == path
    ]
    assert direct_window == [], (
        f"the listener's default action must deny before the function ever runs; the side channel "
        f"reported {direct_window!r} within {window_s:.1f}s of the direct request")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
