"""forward-weighted-and-sticky-target-groups-data-plane."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forward-weighted-and-sticky-target-groups-data-plane"
GROUP = 'data-plane'
SERVICES = ['elbv2']

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


def _http(ctx, url, *, method="GET", headers=None, timeout=20):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _register_lambda_target_awaiting_invoke_permission(elb, tg_arn, target_id, timeout_s=60):
    """RegisterTargets checks lambda:InvokeFunction up front, and the resource
    policy just granted by add_permission propagates with a short lag."""
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


def _retry_dependency(fn, attempts=15, delay=6):
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("DependencyViolation", "InvalidGroup.InUse", "InvalidSubnetID.InUse",
                            "InvalidVpcID.InUse", "InvalidInternetGatewayID.NotFound"):
                raise
            last = exc
            time.sleep(delay)
    raise last


def _provision_vpc_and_subnets(ctx, ec2, num_subnets):
    """Build a routable VPC: an internet-facing ALB needs a real path to the internet,
    not just a VPC id."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": list(_TAGS)}],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _retry_dependency(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": list(_TAGS)}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]][:num_subnets]
    if len(azs) < num_subnets:
        raise AssertionError(f"region exposes {len(azs)} available AZs, need {num_subnets}")

    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.78.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": list(_TAGS)}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda a=assoc_id: ec2.disassociate_route_table(AssociationId=a))
        subnet_ids.append(sid)
    return vpc_id, subnet_ids


def _own_vpc_and_subnets(ctx, num_subnets=2):
    """A routable VPC and public subnets this check creates for the internet-facing ALB."""
    return _provision_vpc_and_subnets(ctx, ctx.client("ec2"), num_subnets)


def _delete_retrying(fn, *, gone, busy=(), timeout_s=0):
    """Teardown delete: done on success or a `gone` code; retries a `busy` code every 2 s while a
    dependency is released, up to timeout_s; raises every other failure."""
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


def _open_http_sg(ctx, vpc_id, port=80):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        # A deleting load balancer's ENIs hold the group briefly: retry only DependencyViolation.
        _delete_retrying(lambda: ec2.delete_security_group(GroupId=sg_id), gone={"InvalidGroup.NotFound"},
                         busy={"DependencyViolation"}, timeout_s=180)

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


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # A listener or deleting load balancer holds the group briefly: retry only ResourceInUse.
        _delete_retrying(lambda: elb.delete_target_group(TargetGroupArn=arn), gone={"TargetGroupNotFound"},
                         busy={"ResourceInUse"}, timeout_s=60)

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


def _forward(target_groups, sticky=None):
    cfg = {"TargetGroups": target_groups}
    if sticky is not None:
        cfg["TargetGroupStickinessConfig"] = sticky
    return [{"Type": "forward", "ForwardConfig": cfg}]


def _sample(ctx, url, n, *, headers=None):
    """Send n requests; return (list_of_bodies, last_header_message)."""
    bodies = []
    last_hdrs = None
    for _ in range(n):
        status, hdrs, body = _http(ctx, url, headers=headers)
        assert status == 200, f"GET {url}: HTTP {status}, body={body[:200]!r}"
        bodies.append(body.strip())
        last_hdrs = hdrs
    return bodies, last_hdrs


def _wait_for_serving(ctx, url, accepted, *, timeout_s=300):
    """Poll until the ALB serves one of `accepted` (DNS + listener convergence)."""
    seen = []

    def probe():
        try:
            status, hdrs, body = _http(ctx, url)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body[:40]}")
        return (status, hdrs, body.strip())

    return _poll_until(
        probe, lambda r: r is not None and r[0] == 200 and r[2] in accepted,
        timeout_s=timeout_s, interval_s=5,
        description=f"ALB serving one of {sorted(accepted)} at {url} (observed: {seen[-6:]})",
    )
# ===== end helpers =====

_FN_SRC = """
import json


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "statusDescription": "200 OK",
        "isBase64Encoded": False,
        "headers": {"Content-Type": "text/plain"},
        "body": "%s",
    }
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A 1:1 weighted forward reaches both target groups, weight 0 excludes one, and
    TargetGroupStickinessConfig mints an AWSALBTG cookie that pins a client to one group.
    """
    elb = ctx.client("elbv2")
    lam = ctx.client("lambda")
    vpc_id, subnet_ids = _own_vpc_and_subnets(ctx)
    sg_id = _open_http_sg(ctx, vpc_id, 80)

    role_arn = _create_lambda_role(ctx)
    fn_a = _create_lambda(ctx, role_arn, _FN_SRC % "TG-A")
    fn_b = _create_lambda(ctx, role_arn, _FN_SRC % "TG-B")

    # Control: both artifacts work when invoked directly, so a routing failure below
    # cannot be blamed on the Lambda.
    for fn, expected in ((fn_a, "TG-A"), (fn_b, "TG-B")):
        payload = json.loads(lam.invoke(FunctionName=fn["name"], Payload=b"{}")["Payload"].read())
        assert payload.get("body") == expected, f"{fn['name']} direct invoke returned {payload!r}"

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg_a = _create_target_group(ctx, TargetType="lambda")
    tg_b = _create_target_group(ctx, TargetType="lambda")
    _allow_elb_invoke(ctx, fn_a["name"], tg_a["TargetGroupArn"])
    _allow_elb_invoke(ctx, fn_b["name"], tg_b["TargetGroupArn"])
    _retry_throttled(lambda: _register_lambda_target_awaiting_invoke_permission(
        elb, tg_a["TargetGroupArn"], fn_a["arn"]))
    _retry_throttled(lambda: _register_lambda_target_awaiting_invoke_permission(
        elb, tg_b["TargetGroupArn"], fn_b["arn"]))

    even = [
        {"TargetGroupArn": tg_a["TargetGroupArn"], "Weight": 1},
        {"TargetGroupArn": tg_b["TargetGroupArn"], "Weight": 1},
    ]
    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=_forward(even, sticky={"Enabled": False}),
    )
    la = listener["ListenerArn"]

    # The weighted shape must survive the round trip, not collapse to one group.
    described = elb.describe_listeners(ListenerArns=[la])["Listeners"][0]
    fwd = described["DefaultActions"][0].get("ForwardConfig", {})
    weights = {tg["TargetGroupArn"]: tg.get("Weight") for tg in fwd.get("TargetGroups", [])}
    assert weights == {tg_a["TargetGroupArn"]: 1, tg_b["TargetGroupArn"]: 1}, described["DefaultActions"]

    url = f"http://{lb['DNSName']}/"
    _wait_for_serving(ctx, url, {"TG-A", "TG-B"})

    # 1. 1:1 weights reach BOTH target groups.
    bodies, hdrs = _sample(ctx, url, 40)
    assert set(bodies) == {"TG-A", "TG-B"}, (
        f"1:1 weighted forward only ever reached {sorted(set(bodies))}; both groups expected"
    )
    # 2. Stickiness disabled => no AWSALBTG cookie is minted.
    cookies = [c.split("=", 1)[0] for c in (hdrs.get_all("Set-Cookie") or [])]
    assert "AWSALBTG" not in cookies, f"AWSALBTG minted with stickiness disabled: {cookies}"

    # 3. Weight 0 excludes a target group completely.
    _retry_throttled(lambda: elb.modify_listener(ListenerArn=la, DefaultActions=_forward([
        {"TargetGroupArn": tg_a["TargetGroupArn"], "Weight": 1},
        {"TargetGroupArn": tg_b["TargetGroupArn"], "Weight": 0},
    ], sticky={"Enabled": False})))

    def _only_a():
        """12 requests' distinct bodies, or None while any request is not a 200."""
        bodies_now = []
        for _ in range(12):
            try:
                status, _hdrs, body = _http(ctx, url)
            except (urllib.error.URLError, OSError):
                return None
            if status != 200:
                return None
            bodies_now.append(body.strip())
        return sorted(set(bodies_now))

    got = _poll_until(
        _only_a, lambda s: s == ["TG-A"], timeout_s=180, interval_s=5,
        description="weight-0 target group being excluded from every response",
    )
    assert got == ["TG-A"], got

    # 4. Stickiness on: the ALB mints AWSALBTG and a replayed cookie pins the group.
    _retry_throttled(lambda: elb.modify_listener(
        ListenerArn=la,
        DefaultActions=_forward(even, sticky={"Enabled": True, "DurationSeconds": 3600}),
    ))

    def _sticky_cookie():
        try:
            _status, hdrs_now, body_now = _http(ctx, url)
        except (urllib.error.URLError, OSError):
            return None
        for raw in hdrs_now.get_all("Set-Cookie") or []:
            if raw.split("=", 1)[0] == "AWSALBTG":
                return (raw.split(";", 1)[0], body_now.strip())
        return None

    cookie, first_body = _poll_until(
        _sticky_cookie, lambda r: r is not None, timeout_s=180, interval_s=5,
        description="ALB minting an AWSALBTG target-group stickiness cookie",
    )
    assert first_body in {"TG-A", "TG-B"}, first_body
    pinned, _ = _sample(ctx, url, 10, headers={"Cookie": cookie})
    assert set(pinned) == {first_body}, (
        f"AWSALBTG cookie {cookie.split('=')[0]} did not pin the target group: "
        f"first={first_body!r} replayed={sorted(set(pinned))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
