"""alb-access-log-lines-are-delivered-to-s3-with-the-documented-fields."""
from __future__ import annotations

import gzip
import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alb-access-log-lines-are-delivered-to-s3-with-the-documented-fields"
GROUP = "cross-service"
SERVICES = ["elbv2", "s3"]

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

_LOG_DELIVERY_PRINCIPAL = "logdelivery.elasticloadbalancing.amazonaws.com"

_CIDR = "10.177.0.0/16"


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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises: accepting input
    AWS refuses must fail as that, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


#: Not-found codes of the deletes this check's teardowns issue: an already-gone resource is clean.
_GONE_CODES = frozenset({
    "LoadBalancerNotFound", "TargetGroupNotFound", "ListenerNotFound", "RuleNotFound",
    "NoSuchEntity", "ResourceNotFoundException", "NoSuchBucket",
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "Gateway.NotAttached",
})


def _safe_cleanup(fn):
    """Teardown wrapper: returns only when the resource is already gone, raises every other failure."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
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


def _create_bucket(ctx):
    """A bucket in the load balancer's own region, emptied then deleted on teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-alblogs-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the ONLY region for which CreateBucket refuses a LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)

    def _drop_bucket():
        # Empties only the bucket this check created.
        for _ in range(20):
            try:
                listing = s3.list_objects_v2(Bucket=name, MaxKeys=1000)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchBucket":
                    raise
                return
            keys = [{"Key": o["Key"]} for o in listing.get("Contents") or []]
            if not keys:
                break
            _safe_cleanup(lambda k=keys: s3.delete_objects(
                Bucket=name, Delete={"Objects": k}))()
        _safe_cleanup(lambda: s3.delete_bucket(Bucket=name))()

    ctx.on_cleanup(_drop_bucket)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": list(_TAGS)})
    return name


def _grant_log_delivery(ctx, bucket, prefix, account, partition):
    s3 = ctx.client("s3")
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": _LOG_DELIVERY_PRINCIPAL},
            "Action": "s3:PutObject",
            "Resource": f"arn:{partition}:s3:::{bucket}/{prefix}/AWSLogs/{account}/*",
        }],
    }))


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
        # _delete_net already retries DependencyViolation while the load balancer's ENIs detach.
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
        # ResourceInUse while a listener or rule being deleted still references the group.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
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
    ctx.on_cleanup(_safe_cleanup(lambda: iam.delete_role(RoleName=name)))
    return arn


def _create_lambda(ctx, role_arn, source):
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
                Code={"ZipFile": buf.getvalue()}, Timeout=20, MemorySize=128,
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


def _lb_attributes(ctx, lb_arn):
    elb = ctx.client("elbv2")
    return {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn)["Attributes"]}


def _enable_access_logs(ctx, lb_arn, bucket, prefix):
    elb = ctx.client("elbv2")
    return elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[
            {"Key": "access_logs.s3.enabled", "Value": "true"},
            {"Key": "access_logs.s3.bucket", "Value": bucket},
            {"Key": "access_logs.s3.prefix", "Value": prefix},
        ],
    )


def _split_log_line(line):
    """Split one access-log entry, honouring the double-quoted fields.

    The format is space-separated with quoted `request`, `user_agent` and the trace/domain fields, so
    a bare split() mangles every entry that has a space in its User-Agent — which is every entry.
    """
    fields = []
    buf = []
    in_quotes = False
    for ch in line:
        if ch == '"':
            in_quotes = not in_quotes
            continue
        if ch == " " and not in_quotes:
            fields.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    fields.append("".join(buf))
    return [f for f in fields if f != ""]


def _all_log_lines(ctx, bucket, prefix, account):
    """Every access-log line under the documented elasticloadbalancing/<region>/ subpath.

    The instant access logging is successfully enabled, AWS separately drops a one-time,
    plaintext `<prefix>/AWSLogs/<account>/ELBAccessLogTestFile` object to prove the bucket
    policy grants write access — it is not gzip-encoded and is not an access-log entry.
    Listing the documented log subpath directly (rather than the whole `prefix`) excludes it
    by construction instead of choking on it in the gzip-magic check below.
    """
    s3 = ctx.client("s3")
    out = []
    token = None
    log_prefix = f"{prefix}/AWSLogs/{account}/elasticloadbalancing/"
    for _ in range(50):
        kwargs = {"Bucket": bucket, "Prefix": log_prefix, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        listing = s3.list_objects_v2(**kwargs)
        for obj in listing.get("Contents") or []:
            key = obj["Key"]
            raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            assert raw[:2] == b"\x1f\x8b", (
                f"access-log object {key!r} does not start with the gzip magic bytes; got "
                f"{raw[:8]!r}"
            )
            text = gzip.decompress(raw).decode("utf-8", "replace")
            for line in text.splitlines():
                if line.strip():
                    out.append((key, line))
        token = listing.get("NextContinuationToken")
        if not token:
            break
    return out
# ===== end helpers =====

_FN_SRC = '''
def lambda_handler(event, context):
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": {"Content-Type": "text/plain"}, "body": "LOGGED-OK"}
'''


# timing:real-time — buffer: 191 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
@tags("axis:happy-path", "cap:c4", "concern:metrics", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """ALB access logs cannot be enabled onto a bucket whose policy does not grant the log-delivery
    principal s3:PutObject; once granted, one log line per request lands in S3 carrying this run's
    User-Agent and request path.
    """
    elb = ctx.client("elbv2")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    prefix = _clamp_name(ctx.unique_name("albprefix-"), 40)

    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, ports=(80,))

    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda(ctx, role_arn, _FN_SRC)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    lb_arn = lb["LoadBalancerArn"]
    partition = lb_arn.split(":")[1]
    lb_id = "/".join(lb_arn.split("/")[-3:])
    _wait_for_lb_active(ctx, lb_arn)

    tg = _create_target_group(ctx, TargetType="lambda")
    tg_arn = tg["TargetGroupArn"]
    _allow_elb_invoke(ctx, fn["name"], tg_arn)
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg_arn, Targets=[{"Id": fn["arn"]}]))
    _create_listener(
        ctx, lb_arn, Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])

    marker = _clamp_name(ctx.unique_name("mk"), 24)
    path = f"/{marker}/logged"
    user_agent = f"sim2real-alblog/{marker}"
    url = f"http://{lb['DNSName']}{path}"

    # POSITIVE CONTROL: the default state is "off", so the refusal below cannot be a no-op.
    before = _lb_attributes(ctx, lb_arn)
    assert before.get("access_logs.s3.enabled") == "false", (
        f"a freshly created load balancer reports access_logs.s3.enabled="
        f"{before.get('access_logs.s3.enabled')!r}, expected 'false'"
    )
    ok = elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "idle_timeout.timeout_seconds", "Value": "70"}])
    assert ok["Attributes"], (
        "ModifyLoadBalancerAttributes rejected an unrelated, valid attribute change; the refusal "
        "asserted below would then say nothing about the bucket policy"
    )

    # ---- leg 1: the bucket has no policy. Enabling access logs must be REFUSED. -------------
    err = _client_error(lambda: _enable_access_logs(ctx, lb_arn, bucket, prefix))
    code = err.get("Code")
    message = err.get("Message")
    assert code == "InvalidConfigurationRequest", (
        f"enabling access logs onto a bucket with no log-delivery policy failed with {code!r} "
        f"({message!r}); expected a configuration refusal"
    )
    expected_message = f"Access Denied for bucket: {bucket}. Please check S3bucket permission"
    assert message == expected_message, (
        f"the refusal message was {message!r}, expected {expected_message!r}: it must implicate "
        f"the BUCKET, otherwise this leg cannot be told apart from a malformed request or a "
        f"missing permission"
    )
    # EFFECT ABSENT via an independent read.
    still_off = _lb_attributes(ctx, lb_arn)
    assert still_off.get("access_logs.s3.enabled") == "false", (
        f"after the refused call access_logs.s3.enabled is "
        f"{still_off.get('access_logs.s3.enabled')!r}, expected the unchanged 'false'"
    )
    assert still_off.get("access_logs.s3.bucket") in ("", None), (
        f"after the refused call access_logs.s3.bucket is "
        f"{still_off.get('access_logs.s3.bucket')!r}, expected it to be unset"
    )

    # ---- leg 2: restore the ONE missing thing. The identical call now succeeds. -------------
    _grant_log_delivery(ctx, bucket, prefix, account, partition)

    def _try_enable():
        """The IDENTICAL call, retried only through the bucket-policy propagation window.

        The retry accepts exactly the refusal the previous leg asserted, so a DIFFERENT error
        still fails the check immediately instead of being retried into a timeout.
        """
        try:
            return _enable_access_logs(ctx, lb_arn, bucket, prefix).get("Attributes") or None
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidConfigurationRequest":
                return None
            raise

    _poll_until(
        _try_enable, lambda r: r is not None, timeout_s=300, interval_s=10,
        description="the identical ModifyLoadBalancerAttributes call succeeding once the bucket "
                    "policy grants the ELB log-delivery principal s3:PutObject",
    )
    after = _lb_attributes(ctx, lb_arn)
    assert after.get("access_logs.s3.enabled") == "true", (
        f"access_logs.s3.enabled is {after.get('access_logs.s3.enabled')!r} after a successful "
        f"enable, expected 'true'"
    )
    assert after.get("access_logs.s3.bucket") == bucket, (
        f"access_logs.s3.bucket is {after.get('access_logs.s3.bucket')!r}, expected {bucket!r}"
    )
    assert after.get("access_logs.s3.prefix") == prefix, (
        f"access_logs.s3.prefix is {after.get('access_logs.s3.prefix')!r}, expected {prefix!r}"
    )

    # ---- leg 3: drive real traffic, then read the result AT THE CONSUMER. -------------------
    n_requests = 12

    def _probe():
        try:
            status, _hdrs, body = _http(ctx, url, headers={"User-Agent": user_agent})
        except (urllib.error.URLError, OSError) as exc:
            return (None, f"<transport: {type(exc).__name__}: {exc}>")
        return (status, body.strip())

    warm = _poll_until(
        _probe, lambda r: r == (200, "LOGGED-OK"), timeout_s=420, interval_s=10,
        description="the ALB serving the Lambda target before the logged batch starts",
    )
    assert warm == (200, "LOGGED-OK"), f"warm-up request returned {warm!r}, expected (200, 'LOGGED-OK')"
    for i in range(n_requests):
        status, _hdrs, body = _http(ctx, url, headers={"User-Agent": user_agent})
        assert (status, body.strip()) == (200, "LOGGED-OK"), (
            f"logged request {i + 1}/{n_requests} returned {(status, body.strip()[:60])!r}, "
            f"expected (200, 'LOGGED-OK'); the line count below is only derivable if every request "
            f"in the batch was served identically"
        )
    # The warm-up request carried the same UA, so the derived expectation includes it.
    expected_lines = n_requests + 1

    def _mine():
        lines = [
            (key, line, _split_log_line(line))
            for key, line in _all_log_lines(ctx, bucket, prefix, account)
        ]
        return [t for t in lines if user_agent in t[1]]

    mine = _poll_until(
        _mine, lambda got: len(got) >= expected_lines, timeout_s=900, interval_s=30,
        description=f"{expected_lines} access-log lines carrying User-Agent {user_agent!r} arriving "
                    f"under s3://{bucket}/{prefix}",
    )
    assert len(mine) == expected_lines, (
        f"S3 holds {len(mine)} access-log lines carrying User-Agent {user_agent!r}, expected exactly "
        f"{expected_lines} — one per request this run sent through the load balancer"
    )

    # The object key layout is part of the contract customers build Athena tables on.
    keys = sorted({key for key, _line, _f in mine})
    expected_key_prefix = f"{prefix}/AWSLogs/{account}/elasticloadbalancing/{ctx.region}/"
    for key in keys:
        assert key.startswith(expected_key_prefix), (
            f"access-log object {key!r} is not under the documented layout "
            f"{expected_key_prefix!r}<yyyy>/<mm>/<dd>/"
        )
        tail = key[len(expected_key_prefix):]
        date_parts = tail.split("/")[:3]
        assert len(date_parts) == 3 and all(p.isdigit() for p in date_parts), (
            f"access-log object {key!r} does not carry a <yyyy>/<mm>/<dd> path after "
            f"{expected_key_prefix!r}; parsed {date_parts!r}"
        )
        assert account in tail and ctx.region in key, (
            f"access-log object name {key!r} must contain the account id {account} and the region "
            f"{ctx.region}"
        )

    # And the entry itself.
    _key, line, fields = mine[0]
    assert len(fields) >= 29, (
        f"an access-log entry parsed into {len(fields)} fields, expected at least 29 (the documented "
        f"format only ever APPENDS fields); line was {line[:300]!r}"
    )
    assert fields[0] == "http", (
        f"the entry's `type` field is {fields[0]!r}, expected 'http' for an HTTP listener; line "
        f"{line[:200]!r}"
    )
    assert fields[2] == lb_id, (
        f"the entry's `elb` field is {fields[2]!r}, expected this load balancer's id {lb_id!r}"
    )
    client_field = fields[3]
    assert ":" in client_field and client_field.rsplit(":", 1)[1].isdigit(), (
        f"the entry's `client:port` field is {client_field!r}, expected <address>:<port>"
    )
    request_field = next((f for f in fields if path in f), None)
    assert request_field is not None, (
        f"no field of the entry contains the requested path {path!r}; fields were {fields!r}"
    )
    assert request_field.startswith("GET http://"), (
        f"the entry's `request` field is {request_field!r}, expected it to start with 'GET http://'"
    )
    assert fields[8] == "200", (
        f"the entry's `elb_status_code` field is {fields[8]!r}, expected '200'; every request in the "
        f"batch was answered 200. Full line: {line[:300]!r}"
    )
    assert fields[9] == "200", (
        f"the entry's `target_status_code` field is {fields[9]!r}, expected '200' — the Lambda "
        f"target returned 200, so the load balancer must record the TARGET's code too"
    )
    # Positional fields 14..22 are the part of the documented order that has been stable for years,
    # and index 16 is the sharpest of them: an emulator that emits a plausible-looking line will not
    # put THIS run's target group ARN there.
    assert fields[14] == "-" and fields[15] == "-", (
        f"on an HTTP listener `ssl_cipher`/`ssl_protocol` must be '-'; got "
        f"{(fields[14], fields[15])!r}. Full line: {line[:300]!r}"
    )
    assert fields[16] == tg_arn, (
        f"the entry's `target_group_arn` field is {fields[16]!r}, expected the target group this "
        f"check created and registered: {tg_arn!r}"
    )
    assert fields[17].startswith("Root=1-"), (
        f"the entry's `trace_id` field is {fields[17]!r}, expected it to begin 'Root=1-'"
    )
    assert fields[19] == "-", (
        f"the entry's `chosen_cert_arn` field is {fields[19]!r}, expected '-' on an HTTP listener"
    )
    assert fields[20] == "0", (
        f"the entry's `matched_rule_priority` field is {fields[20]!r}, expected '0' — the request was "
        f"served by the listener's DEFAULT rule, whose documented priority is 0"
    )
    assert fields[22] == "forward", (
        f"the entry's `actions_executed` field is {fields[22]!r}, expected 'forward'"
    )

    # A read must not create log lines: re-listing must return the same set.
    again = _mine()
    assert len(again) == len(mine), (
        f"re-reading the bucket returned {len(again)} matching lines, expected the unchanged "
        f"{len(mine)} — reading access logs must not produce access logs"
    )


# A load balancer in this VPC deletes asynchronously and leaves its ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries that code in one shared window, then raises naming the ENIs.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
