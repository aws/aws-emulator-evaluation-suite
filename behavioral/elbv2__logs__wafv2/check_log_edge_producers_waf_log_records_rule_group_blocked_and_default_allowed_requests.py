"""log-edge-producers-waf-log-records-rule-group-blocked-and-default-allowed-requests."""
from __future__ import annotations

import json
import socket
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-edge-producers-waf-log-records-rule-group-blocked-and-default-allowed-requests"
GROUP = "access-logs"
SERVICES = ["elbv2", "logs", "wafv2"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})
#: WAF's view of a fresh resource, and of its own sub-resources, is eventually consistent.
#: These are retried; nothing else is.
_WAF_TRANSIENT = frozenset({"WAFUnavailableEntityException", "WAFOptimisticLockException",
                            "WAFInternalErrorException", "WAFAssociatedItemException",
                            "ThrottlingException"})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]
_CIDR = "10.180.0.0/16"


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Bounded retry. RAISES on timeout — never returns its last value."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retrying_delete(what, fn, *, attempts=40, interval_s=8):
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
                if code.endswith("NotFound") or code.endswith(".NotFound") or code in ("NoSuchBucket", "ResourceNotFoundException"):
                    return
                last = exc
            time.sleep(interval_s)
        raise RuntimeError(f"{what}: {last!r}")

    return _wrapped



def _own_vpc(ctx, azs):
    """A VPC this check creates, with an IGW and one public subnet per AZ given."""
    ec2 = ctx.client("ec2")

    def _spec(kind):
        return [{"ResourceType": kind, "Tags": list(_TAGS)}]

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(_retrying_delete(f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))
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
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{base[0]}.{base[1]}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=_spec("subnet"))["Subnet"]["SubnetId"]
        ctx.on_cleanup(_retrying_delete(
            f"subnet {sid}", lambda s=sid: ec2.delete_subnet(SubnetId=s)))
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_retrying_delete(
            f"rtb association {assoc}",
            lambda a=assoc: ec2.disassociate_route_table(AssociationId=a), attempts=3))
        subnets.append(sid)
    return vpc_id, subnets


def _security_group(ctx, vpc_id, name_prefix, ingress):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name(name_prefix), Description="sim2real alb access-log check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(_retrying_delete(
        f"security group {sg_id}", lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress)
    return sg_id


def _create_load_balancer(ctx, subnets, sg_id):
    elb = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-lel-")
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
            except ClientError:
                return
            time.sleep(4)
        raise RuntimeError(f"load balancer {arn} still described after 360s")

    ctx.on_cleanup(_drop_lb)
    lb = _poll_until(
        ctx,
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] != "provisioning", timeout_s=600, interval_s=2,
        description=f"load balancer {name} leaving provisioning")
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb




def _waf_retry(fn, *, timeout_s=420, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _WAF_TRANSIENT \
                    or time.monotonic() > deadline:
                raise
        time.sleep(interval_s)


def _vis(name):
    return {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", "")[:128]}


def _waf_delete(w, kind, name, rid):
    """Teardown-only: fetch a fresh lock token each attempt (it changes on every mutation)."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    arg = {"web_acl": "WebACL", "rule_group": "RuleGroup"}[kind]

    def _once():
        token = getter(Name=name, Scope="REGIONAL", Id=rid)["LockToken"]
        deleter(Name=name, Scope="REGIONAL", Id=rid, LockToken=token)

    def _wrapped():
        last = None
        for _ in range(150):
            try:
                _once()
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "WAFNonexistentItemException":
                    return
                last = exc
            time.sleep(2)
        raise RuntimeError(f"wafv2 {arg} {name}: {last!r}")

    return _wrapped


def _raw_get(ctx, host, path, headers):
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
           + "Connection: close\r\n\r\n").encode("ascii")
    with socket.create_connection(ctx.endpoint_host(host, 80), timeout=20) as sock:
        sock.sendall(req)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    resp = b"".join(chunks)
    head, _, body = resp.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else None
    return status, body.decode("utf-8", "replace")


def _waf_records(logs, group, marker, start_ms):
    out = []
    kwargs = {"logGroupName": group, "startTime": start_ms, "filterPattern": f'"{marker}"'}
    while True:
        page = logs.filter_log_events(**kwargs)
        out.extend(json.loads(e["message"]) for e in page.get("events", []))
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A WAF web ACL on an ALB logs one record per request: a rule-group BLOCK names the group and
    its inner rule, an unmatched request is ALLOW by Default_Action, a COUNT rule is non-terminating
    on both, and a redacted header reads REDACTED while an unredacted one is verbatim.
    """
    elb = ctx.client("elbv2")
    w = ctx.client("wafv2")
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    marker = ctx.unique_name("m")
    secret = ctx.unique_name("secret-")
    keep = ctx.unique_name("keep-")
    ec2 = ctx.client("ec2")
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, f"{ctx.region} exposes {azs!r}; an ALB needs two available AZs"

    # WAF only logs to a group whose name starts aws-waf-logs-.
    group = ctx.unique_name("aws-waf-logs-sim2real-lel-")
    logs.create_log_group(logGroupName=group, tags={t["Key"]: t["Value"] for t in _TAGS})
    ctx.on_cleanup(_retrying_delete(
        f"log group {group}", lambda: logs.delete_log_group(logGroupName=group), attempts=5))
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]
    group_arn = group_arn[:-2] if group_arn.endswith(":*") else group_arn

    rg_name = ctx.unique_name("sim2real-lel-rg-")
    inner_rule = f"blk-{marker}"
    rg = _waf_retry(lambda: w.create_rule_group(
        Name=rg_name, Scope="REGIONAL", Capacity=20, VisibilityConfig=_vis(rg_name),
        Tags=list(_TAGS),
        Rules=[{"Name": inner_rule, "Priority": 0, "Action": {"Block": {}},
                "VisibilityConfig": _vis(inner_rule),
                "Statement": {"ByteMatchStatement": {
                    "SearchString": marker.encode(), "PositionalConstraint": "EXACTLY",
                    "FieldToMatch": {"SingleHeader": {"Name": "x-sim2real-block"}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}}]))["Summary"]
    ctx.on_cleanup(_waf_delete(w, "rule_group", rg_name, rg["Id"]))

    acl_name = ctx.unique_name("sim2real-lel-acl-")
    count_rule, rg_ref_rule = f"cnt-{marker}", f"rg-{marker}"
    acl = _waf_retry(lambda: w.create_web_acl(
        Name=acl_name, Scope="REGIONAL", DefaultAction={"Allow": {}},
        VisibilityConfig=_vis(acl_name), Tags=list(_TAGS),
        Rules=[
            {"Name": count_rule, "Priority": 0, "Action": {"Count": {}},
             "VisibilityConfig": _vis(count_rule),
             "Statement": {"ByteMatchStatement": {
                 "SearchString": f"/{marker}/".encode(), "PositionalConstraint": "STARTS_WITH",
                 "FieldToMatch": {"UriPath": {}},
                 "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}},
            {"Name": rg_ref_rule, "Priority": 1, "OverrideAction": {"None": {}},
             "VisibilityConfig": _vis(rg_ref_rule),
             "Statement": {"RuleGroupReferenceStatement": {"ARN": rg["ARN"]}}},
        ]))["Summary"]
    ctx.on_cleanup(_waf_delete(w, "web_acl", acl_name, acl["Id"]))

    vpc_id, subnets = _own_vpc(ctx, azs[:2])
    lb_sg = _security_group(ctx, vpc_id, "sim2real-lel-lbsg-", [
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}])
    lb = _create_load_balancer(ctx, subnets, lb_sg)
    lb_arn, dns = lb["LoadBalancerArn"], lb["DNSName"]
    lb_id = lb_arn.split(":loadbalancer/", 1)[1]
    fixed = f"origin-{marker}"
    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "200", "ContentType": "text/plain", "MessageBody": fixed}}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_retrying_delete(
        "listener", lambda: elb.delete_listener(ListenerArn=listener_arn), attempts=3))

    _waf_retry(lambda: w.put_logging_configuration(LoggingConfiguration={
        "ResourceArn": acl["ARN"], "LogDestinationConfigs": [group_arn],
        "RedactedFields": [{"SingleHeader": {"Name": "x-sim2real-secret"}}]}))
    ctx.on_cleanup(_retrying_delete(
        "waf logging configuration",
        lambda: w.delete_logging_configuration(ResourceArn=acl["ARN"]), attempts=3))
    _waf_retry(lambda: w.associate_web_acl(WebACLArn=acl["ARN"], ResourceArn=lb_arn))
    ctx.on_cleanup(_retrying_delete(
        "web acl association", lambda: w.disassociate_web_acl(ResourceArn=lb_arn), attempts=5))

    ua = f"sim2real-lel-waf/{marker}"
    base = {"User-Agent": ua, "x-sim2real-secret": secret, "x-sim2real-keep": keep}

    def _get(path, block):
        hdrs = dict(base, **({"x-sim2real-block": marker} if block else {}))
        try:
            return _raw_get(ctx, dns, path, hdrs)
        except OSError as exc:
            return (None, repr(exc))

    # Propagation: every ALB node must enforce the ACL. Require consecutive agreeing answers on
    # throwaway paths, so the two graded requests below are each logged exactly once.
    streak = {"n": 0, "i": 0}

    def _both_enforced():
        streak["i"] += 1
        a = _get(f"/{marker}/warm-allow-{streak['i']}", False)
        b = _get(f"/{marker}/warm-block-{streak['i']}", True)
        good = a == (200, fixed) and b[0] == 403
        streak["n"] = streak["n"] + 1 if good else 0
        return streak["n"], a, b

    _poll_until(ctx, _both_enforced, lambda r: r[0] >= 4, timeout_s=600, interval_s=2,
                description="the web ACL enforced on every ALB node (4 consecutive agreeing pairs)")

    start_ms = int((time.time() - 300) * 1000)
    allowed_path, blocked_path = f"/{marker}/allowed", f"/{marker}/blocked"
    allowed = _get(allowed_path, False)
    blocked = _get(blocked_path, True)
    assert allowed == (200, fixed), (
        f"the unflagged request returned {allowed!r}, expected the ALB's fixed response "
        f"(200, {fixed!r})")
    assert blocked[0] == 403 and fixed not in blocked[1], (
        f"the flagged request returned {blocked!r}; expected WAF's 403 and NOT the origin body")

    def _graded():
        recs = _waf_records(logs, group, marker, start_ms)
        return {p: [r for r in recs if r.get("httpRequest", {}).get("uri") == p]
                for p in (allowed_path, blocked_path)}

    got = _poll_until(ctx, _graded, lambda g: all(g.values()), timeout_s=900, interval_s=2,
                      description=f"WAF log records for both graded requests in {group}")
    for p, recs in got.items():
        print(f"[waf-record {p}] {json.dumps(recs[0], sort_keys=True)}")
        assert len(recs) == 1, f"request {p!r} was logged {len(recs)} times, expected once"
    a_rec, b_rec = got[allowed_path][0], got[blocked_path][0]

    # ---- the BLOCK, attributed to the rule group and to the rule inside it. --------------------
    assert b_rec["action"] == "BLOCK", f"blocked record action is {b_rec['action']!r}"
    # The value is 'GROUP' for a customer rule group.
    assert b_rec["terminatingRuleType"] == "GROUP", (
        f"blocked record terminatingRuleType is {b_rec['terminatingRuleType']!r}, expected "
        f"'GROUP' — the terminating rule is a rule-group reference")
    assert b_rec["terminatingRuleId"] == rg_ref_rule, (
        f"blocked record terminatingRuleId is {b_rec['terminatingRuleId']!r}, expected the web ACL "
        f"rule that references the group, {rg_ref_rule!r}")
    rgl = [g for g in b_rec.get("ruleGroupList") or [] if g.get("ruleGroupId") == rg["ARN"]]
    assert len(rgl) == 1, (
        f"blocked record ruleGroupList is {b_rec.get('ruleGroupList')!r}; expected one entry for "
        f"{rg['ARN']!r}")
    term = rgl[0].get("terminatingRule") or {}
    assert (term.get("ruleId"), term.get("action")) == (inner_rule, "BLOCK"), (
        f"blocked record ruleGroupList[].terminatingRule is {term!r}, expected ruleId "
        f"{inner_rule!r} action BLOCK")

    # ---- the ALLOW, by the default action. -----------------------------------------------------
    assert a_rec["action"] == "ALLOW", f"allowed record action is {a_rec['action']!r}"
    assert (a_rec["terminatingRuleId"], a_rec["terminatingRuleType"]) == (
        "Default_Action", "REGULAR"), (
        f"allowed record terminating rule is {a_rec['terminatingRuleId']!r}/"
        f"{a_rec['terminatingRuleType']!r}, expected 'Default_Action'/'REGULAR'")
    # The group WAS evaluated for the allowed request, and terminated nothing.
    a_rgl = [g for g in a_rec.get("ruleGroupList") or [] if g.get("ruleGroupId") == rg["ARN"]]
    assert len(a_rgl) == 1 and a_rgl[0].get("terminatingRule") is None, (
        f"allowed record ruleGroupList is {a_rec.get('ruleGroupList')!r}; expected the group "
        f"listed with terminatingRule null")

    # ---- the COUNT rule matched both, and terminated neither. ----------------------------------
    for label, rec in (("allowed", a_rec), ("blocked", b_rec)):
        ntm = [(r.get("ruleId"), r.get("action"))
               for r in rec.get("nonTerminatingMatchingRules") or []]
        assert ntm == [(count_rule, "COUNT")], (
            f"{label} record nonTerminatingMatchingRules is {ntm!r}, expected "
            f"[({count_rule!r}, 'COUNT')]")
        # ---- provenance: which ACL, which load balancer, which request. ------------------------
        assert rec["webaclId"] == acl["ARN"], f"{label} record webaclId is {rec['webaclId']!r}"
        assert rec["httpSourceName"] == "ALB", (
            f"{label} record httpSourceName is {rec['httpSourceName']!r}, expected 'ALB'")
        assert rec["httpSourceId"] == f"{account}-{lb_id}", (
            f"{label} record httpSourceId is {rec['httpSourceId']!r}, expected "
            f"{account}-{lb_id!r}")
        req = rec["httpRequest"]
        assert (req["httpMethod"], req["args"]) == ("GET", ""), (
            f"{label} record method/args are {(req['httpMethod'], req['args'])!r}")
        hdrs = {h["name"].lower(): h["value"] for h in req["headers"]}
        assert hdrs.get("x-sim2real-secret") == "REDACTED", (
            f"{label} record x-sim2real-secret header is {hdrs.get('x-sim2real-secret')!r}, "
            f"expected 'REDACTED'")
        assert secret not in json.dumps(rec), f"{label} record leaks the redacted value {secret!r}"
        assert hdrs.get("x-sim2real-keep") == keep and hdrs.get("user-agent") == ua, (
            f"{label} record unredacted headers are {hdrs!r}; x-sim2real-keep and user-agent must "
            f"arrive verbatim")
    assert "x-sim2real-block" not in {h["name"].lower() for h in a_rec["httpRequest"]["headers"]}
    assert {h["name"].lower(): h["value"] for h in b_rec["httpRequest"]["headers"]}.get(
        "x-sim2real-block") == marker, "the blocked record does not carry the header that matched"
    assert a_rec["httpRequest"]["clientIp"] == b_rec["httpRequest"]["clientIp"], (
        "two requests from this host were logged with different clientIp values")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
