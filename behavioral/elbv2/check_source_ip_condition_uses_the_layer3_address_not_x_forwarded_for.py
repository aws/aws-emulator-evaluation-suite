"""source-ip-condition-uses-the-layer3-address-not-x-forwarded-for."""
from __future__ import annotations

import io
import ipaddress
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "source-ip-condition-uses-the-layer3-address-not-x-forwarded-for"
GROUP = "data-plane"
SERVICES = ["elbv2"]

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

_CIDR = "10.176.0.0/16"

#: RFC 5737 TEST-NET-1. Reserved for documentation, never routable, so it can never be the runner's
#: egress address. That makes the negative leg STRUCTURALLY unsatisfiable rather than a race.
_UNREACHABLE_CIDR = "192.0.2.0/24"
_UNREACHABLE_ADDR = "192.0.2.7"


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
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


#: The not-found answers of this check's teardown calls: the resource is already gone.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound",
    "InvalidRouteTableID.NotFound", "InvalidSubnetID.NotFound", "InvalidAssociationID.NotFound",
    "InvalidGroup.NotFound", "ListenerNotFound", "RuleNotFound", "TargetGroupNotFound",
    "NoSuchEntity", "ResourceNotFoundException",
})


def _safe_cleanup(fn):
    """A teardown step that treats a not-found answer as done and raises every other error."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _GONE:
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
        # _delete_net retries DependencyViolation while the load balancer's interfaces release.
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
        """A target group still referenced by a deleting listener refuses with ResourceInUse."""
        deadline = time.monotonic() + 120.0
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
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


def _fixed(body, status="200", content_type="text/plain"):
    return [{"Type": "fixed-response", "FixedResponseConfig": {
        "StatusCode": status, "ContentType": content_type, "MessageBody": body}}]


def _wait_for_body(ctx, url, expected, *, headers=None, timeout_s=300, description=""):
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {type(exc).__name__}: {exc}>")
            return None
        seen.append(f"{status}:{body.strip()[:32]}")
        return (status, body.strip())

    return _poll_until(
        probe, lambda r: r == (200, expected), timeout_s=timeout_s, interval_s=5,
        description=f"{description or f'{expected!r} at {url}'} (observed: {seen[-8:]})",
    )

_FN_SRC = '''
import json


def lambda_handler(event, context):
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(event.get("headers") or {})}
'''


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A source-ip rule built from the client address the ALB reports routes the request; with an
    unsatisfiable TEST-NET-1 CIDR, even with a matching client-supplied X-Forwarded-For, it falls
    through, and once restored it wins again; the forbidden 255.255.255.255/32 CIDR is refused."""
    elb = ctx.client("elbv2")

    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, ports=(80,))

    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda(ctx, role_arn, _FN_SRC)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(ctx, TargetType="lambda")
    tg_arn = tg["TargetGroupArn"]
    _allow_elb_invoke(ctx, fn["name"], tg_arn)
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg_arn, Targets=[{"Id": fn["arn"]}]))

    slug = _clamp_name(ctx.unique_name("s"), 20)
    echo_path, src_path = f"/{slug}/echo", f"/{slug}/src"
    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=_fixed("DEFAULT-RULE"))
    listener_arn = listener["ListenerArn"]

    echo_rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=5,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": [echo_path]}}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}], Tags=list(_TAGS),
    ))["Rules"][0]
    ctx.on_cleanup(_safe_cleanup(lambda: elb.delete_rule(RuleArn=echo_rule["RuleArn"])))

    base = f"http://{lb['DNSName']}"

    # ---- derive the expected CIDR from the LOAD BALANCER's own report. ----------------------
    def _echo():
        try:
            status, _hdrs, body = _http(ctx, f"{base}{echo_path}")
        except (urllib.error.URLError, OSError):
            return None
        if status != 200:
            return None
        try:
            return json.loads(body)
        except ValueError:
            return None

    echoed = _poll_until(
        _echo, lambda r: isinstance(r, dict) and "x-forwarded-for" in r,
        timeout_s=420, interval_s=10,
        description="the Lambda target echoing back an x-forwarded-for header attached by the ALB",
    )
    xff = echoed["x-forwarded-for"]
    client_ip = xff.split(",")[0].strip()
    parsed = ipaddress.ip_address(client_ip)  # raises ValueError on anything that is not an address
    assert parsed.version == 4, (
        f"the ALB reported x-forwarded-for={xff!r}; this check builds an IPv4 /32 from its first "
        f"entry and got {client_ip!r} (version {parsed.version})"
    )
    assert not parsed.is_unspecified, (
        f"the ALB reported the client address as {client_ip!r}; a /32 built from the unspecified "
        f"address could never match"
    )
    my_cidr = f"{client_ip}/32"

    # ---- two rules, one path. The winner is named by the body. ------------------------------
    src_rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=20,
        Conditions=[
            {"Field": "path-pattern", "PathPatternConfig": {"Values": [src_path]}},
            {"Field": "source-ip", "SourceIpConfig": {"Values": [my_cidr]}},
        ],
        Actions=_fixed("BY-SOURCE-IP"), Tags=list(_TAGS),
    ))["Rules"][0]
    src_rule_arn = src_rule["RuleArn"]
    ctx.on_cleanup(_safe_cleanup(lambda: elb.delete_rule(RuleArn=src_rule_arn)))

    fallthrough = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=30,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": [src_path]}}],
        Actions=_fixed("FELL-THROUGH"), Tags=list(_TAGS),
    ))["Rules"][0]
    ctx.on_cleanup(_safe_cleanup(lambda: elb.delete_rule(RuleArn=fallthrough["RuleArn"])))

    # The condition must survive the control-plane round trip in the modelled shape.
    described = {r["Priority"]: r for r in elb.describe_rules(
        ListenerArn=listener_arn)["Rules"]}
    src_conds = {c["Field"]: c for c in described["20"]["Conditions"]}
    assert src_conds["source-ip"]["SourceIpConfig"]["Values"] == [my_cidr], (
        f"DescribeRules reports SourceIpConfig "
        f"{src_conds['source-ip'].get('SourceIpConfig')!r}, expected Values == [{my_cidr!r}]"
    )

    # ---- leg 1: positive control — the derived /32 wins. ------------------------------------
    _wait_for_body(ctx, f"{base}{src_path}", "BY-SOURCE-IP", timeout_s=420,
                   description=f"the source-ip rule for {my_cidr} winning the request")

    # ---- always-invalid-input negative: the documented forbidden CIDR. ----------------------
    err = _client_error(lambda: elb.modify_rule(
        RuleArn=src_rule_arn,
        Conditions=[
            {"Field": "path-pattern", "PathPatternConfig": {"Values": [src_path]}},
            {"Field": "source-ip", "SourceIpConfig": {"Values": ["255.255.255.255/32"]}},
        ],
    ))
    code = err.get("Code")
    assert code == "ValidationError", (
        f"ModifyRule with the documented-forbidden CIDR 255.255.255.255/32 failed with {code!r} "
        f"({err.get('Message')!r}); expected a validation refusal"
    )
    assert err.get("Message") == "The specified value '255.255.255.255/32' is not a valid CIDR block", (
        f"unexpected refusal message: {err.get('Message')!r}"
    )
    # EFFECT ABSENT: the refused CIDR did not land, so the rule still serves the /32.
    still = {c["Field"]: c for c in elb.describe_rules(
        RuleArns=[src_rule_arn])["Rules"][0]["Conditions"]}
    assert still["source-ip"]["SourceIpConfig"]["Values"] == [my_cidr], (
        f"after the refused ModifyRule the rule's SourceIpConfig is "
        f"{still['source-ip'].get('SourceIpConfig')!r}, expected the unchanged [{my_cidr!r}]"
    )
    _wait_for_body(ctx, f"{base}{src_path}", "BY-SOURCE-IP", timeout_s=120,
                   description="the rule still serving after a refused ModifyRule")

    # ---- leg 2: break EXACTLY one thing — the CIDR. -----------------------------------------
    _retry_throttled(lambda: elb.modify_rule(
        RuleArn=src_rule_arn,
        Conditions=[
            {"Field": "path-pattern", "PathPatternConfig": {"Values": [src_path]}},
            {"Field": "source-ip", "SourceIpConfig": {"Values": [_UNREACHABLE_CIDR]}},
        ],
    ))
    _wait_for_body(ctx, f"{base}{src_path}", "FELL-THROUGH", timeout_s=300,
                   description=f"the request falling through to priority 30 once the source-ip "
                               f"condition names the unroutable {_UNREACHABLE_CIDR}")

    # THE DISCRIMINATOR: X-Forwarded-For must NOT satisfy a source-ip condition.
    status, _hdrs, body = _http(
        ctx, f"{base}{src_path}", headers={"X-Forwarded-For": _UNREACHABLE_ADDR})
    assert (status, body.strip()) == (200, "FELL-THROUGH"), (
        f"with the source-ip condition set to {_UNREACHABLE_CIDR} and the client sending "
        f"X-Forwarded-For: {_UNREACHABLE_ADDR}, the load balancer served "
        f"{(status, body.strip()[:40])!r}; expected (200, 'FELL-THROUGH') — a source-ip condition "
        f"matches the layer-3 address and is explicitly NOT satisfied by X-Forwarded-For"
    )
    # Same request, header naming the real client address: still must not satisfy it either.
    status2, _h2, body2 = _http(ctx, f"{base}{src_path}", headers={"X-Forwarded-For": client_ip})
    assert (status2, body2.strip()) == (200, "FELL-THROUGH"), (
        f"with X-Forwarded-For: {client_ip} (the real client address) and the condition set to "
        f"{_UNREACHABLE_CIDR}, the load balancer served {(status2, body2.strip()[:40])!r}; expected "
        f"(200, 'FELL-THROUGH')"
    )

    # ---- leg 3: restore the ONE thing that changed. -----------------------------------------
    _retry_throttled(lambda: elb.modify_rule(
        RuleArn=src_rule_arn,
        Conditions=[
            {"Field": "path-pattern", "PathPatternConfig": {"Values": [src_path]}},
            {"Field": "source-ip", "SourceIpConfig": {"Values": [my_cidr]}},
        ],
    ))
    _wait_for_body(ctx, f"{base}{src_path}", "BY-SOURCE-IP", timeout_s=300,
                   description=f"the identical request winning again once the source-ip condition "
                               f"is back to {my_cidr} — so the fall-through was attributable to the "
                               f"CIDR alone")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
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
