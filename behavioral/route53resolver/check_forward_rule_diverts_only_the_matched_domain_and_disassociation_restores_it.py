"""forward-rule-diverts-only-the-matched-domain-and-disassociation-restores-it."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forward-rule-diverts-only-the-matched-domain-and-disassociation-restores-it"
GROUP = "resolver-rule"
SERVICES = ["route53resolver"]

_SCENARIO = "r53r-forward-diverts"

_CIDR = "10.61.0.0/16"
_BASE = _CIDR.split("/")[0].rsplit(".", 2)[0]


# budget.cleanup_timeout for behavioral/route53resolver: once teardown starts, every teardown wait
# shares one deadline inside it.
_TEARDOWN_RETRY_S = 900.0
_TEARDOWN: dict = {}


def _on_cleanup(ctx, fn):
    """Register fn as a teardown; the first one to run starts the shared teardown deadline."""
    def _run():
        # A margin inside the budget, so a teardown raises its own error before the runner gives up.
        _TEARDOWN.setdefault("deadline", time.time() + _TEARDOWN_RETRY_S - 120.0)
        fn()
    ctx.on_cleanup(_run)


def _wait_deadline(own_s):
    """Deadline of a wait: own_s ahead, never past the shared deadline once teardown runs."""
    own = time.time() + own_s
    return min(own, _TEARDOWN["deadline"]) if "deadline" in _TEARDOWN else own


def _drop(what, fn, ident, *, gone, busy=()):
    """Bounded teardown delete: the operation's documented not-found code (``gone``) is success,
    a ``busy`` refusal from a dependency still draining is retried every 2 s, the rest raise."""
    deadline = _wait_deadline(300)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            if code == gone:
                return
            if code not in busy:
                raise
            if time.time() >= deadline:
                raise RuntimeError(f"{what} {ident} was not deleted: {exc}") from exc
        time.sleep(2)


def _rig_vpc(ctx, scenario, subnet_count):
    """Create a dedicated VPC with `subnet_count` subnets in distinct AZs; return ids.

    A default VPC may lack subnets in two AZs, so none is relied on; a quota refusal fails loudly.
    """
    ec2 = ctx.client("ec2")
    kv = [{"Key": "sim2real", "Value": scenario}]
    spec = [{"ResourceType": "vpc", "Tags": kv}]
    try:
        vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=spec)["Vpc"]["VpcId"]
    except ClientError as exc:
        raise AssertionError(
            "this check must own its VPC (B10: no ambient default VPC) and create_vpc was "
            f"refused: {exc.response.get('Error', {}).get('Code')!r} -- {exc}") from exc
    _on_cleanup(ctx, lambda v=vpc_id: _drop(
        "vpc", lambda: ec2.delete_vpc(VpcId=v), v, gone="InvalidVpcID.NotFound", busy=("DependencyViolation",)))
    # Route 53 Resolver answers at 169.254.169.253 only when DNS support is on, and creates its
    # autodefined rules only when DNS hostnames is on. Both are set explicitly rather than
    # inherited, because a non-default VPC defaults EnableDnsHostnames to false.
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = sorted(
        a["ZoneName"] for a in ec2.describe_availability_zones(Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
        ])["AvailabilityZones"])
    assert len(azs) >= subnet_count, (
        f"region {ctx.region} exposes {len(azs)} usable AZs and this check needs {subnet_count} "
        f"distinct ones: {azs!r}")
    subnets = []
    for i, az in enumerate(azs[:subnet_count]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{_BASE}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": kv}])["Subnet"]["SubnetId"]
        subnets.append(sid)
        _on_cleanup(ctx, lambda x=sid: _drop(
            "subnet", lambda: ec2.delete_subnet(SubnetId=x), x, gone="InvalidSubnetID.NotFound",
            busy=("DependencyViolation",)))
    groups = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]
    assert groups, (
        f"the VPC {vpc_id} this check just created reports no default security group, so nothing "
        f"can be placed in it")
    return vpc_id, subnets, groups[0]["GroupId"]


# A pure-stdlib DNS querier deployed as a Lambda function with a VPC ENI: Route 53 Resolver
# answers only sources inside the VPC. It parses the wire format and returns the rcode plus every
# answer record's name/ttl/type/rdata.
_DNS_LAMBDA = r"""
import random
import socket
import struct

_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
_TYPENUM = {v: k for k, v in _TYPES.items()}
_VPC_RESOLVER = "169.254.169.253"


def _enc(name):
    out = b""
    for lab in name.rstrip(".").split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def _dec(buf, off):
    labels = []
    after = None
    while True:
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            if after is None:
                after = off + 2
            off = ptr
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode("latin-1"))
        off += 1 + ln
    return ".".join(labels), (after if after is not None else off)


def _local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((_VPC_RESOLVER, 53))
        return s.getsockname()[0]
    finally:
        s.close()


def _one(qname, qtype, server, timeout):
    tid = random.randrange(1, 65535)
    pkt = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    pkt += _enc(qname) + struct.pack("!HH", _TYPENUM[qtype], 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(65535)
    except socket.timeout:
        return {"query": qname, "qtype": qtype, "rcode": "TIMEOUT", "answers": []}
    finally:
        s.close()
    rid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = _dec(data, off)
        off += 4
    answers = []
    for _ in range(an):
        nm, off = _dec(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            val = ".".join(str(b) for b in data[off:off + 4])
        elif rtype in (2, 5, 12):
            val, _ = _dec(data, off)
        elif rtype == 16:
            val = data[off + 1:off + 1 + data[off]].decode("latin-1")
        else:
            val = data[off:off + rdlen].hex()
        off += rdlen
        answers.append({"name": nm, "ttl": ttl, "type": _TYPES.get(rtype, str(rtype)),
                        "rdata": val})
    return {"query": qname, "qtype": qtype, "id_match": rid == tid,
            "rcode": _RCODES.get(flags & 0xF, str(flags & 0xF)),
            "answers": answers}


def handler(event, context):
    server = event.get("server", _VPC_RESOLVER)
    timeout = float(event.get("timeout", 5.0))
    return {"src_ip": _local_ip(),
            "results": [_one(q["name"], q.get("type", "A"), server, timeout)
                        for q in event["queries"]]}
"""

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_VPC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _dig_in(ctx, scenario, subnet_id, sg_id):
    """Place the stdlib querier in `subnet_id`; return (dig, release).

    `release` deletes the function and waits for its Lambda VPC ENI, which can take minutes to
    be reclaimed, to leave the subnet; the body calls it so the subnet and VPC deletes can succeed.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    cwl = ctx.client("logs")
    kv = [{"Key": "sim2real", "Value": scenario}]

    role = ctx.unique_name("sim2real-r53r-dnsfn-")
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=_TRUST,
                               Description="sim2real in-VPC DNS querier", Tags=kv)["Role"]["Arn"]
    _on_cleanup(ctx, lambda n=role: _drop(
        "role", lambda: iam.delete_role(RoleName=n), n, gone="NoSuchEntity", busy=("DeleteConflict",)))
    iam.attach_role_policy(RoleName=role, PolicyArn=_VPC_EXEC)
    _on_cleanup(ctx, lambda n=role: _drop(
        "role-policy", lambda: iam.detach_role_policy(RoleName=n, PolicyArn=_VPC_EXEC), n,
        gone="NoSuchEntity"))

    fn = ctx.unique_name("sim2real-r53r-dig-")
    # create_role returns before Lambda can assume the role and no API reports when it becomes
    # usable, so the bounded retry sits on the first call that needs the permission.
    deadline = time.time() + 180
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip_bytes(_DNS_LAMBDA)}, Timeout=30, MemorySize=256,
                VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
                Tags={"sim2real": scenario})
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            assert time.time() < deadline, f"Lambda never accepted role {role_arn!r}: {exc}"
            time.sleep(2)

    def _drop_log_group(g=f"/aws/lambda/{fn}"):
        # Lambda, not this check, creates /aws/lambda/<fn> on the first invoke, untagged.
        try:
            cwl.delete_log_group(logGroupName=g)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    _on_cleanup(ctx, _drop_log_group)

    # The function cannot be invoked until its VPC ENI exists; State is the observable condition.
    deadline = time.time() + _budget_s(ctx, 600)
    while True:
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Active":
            break
        if cfg["State"] == "Pending" and time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"function {fn} to become Active: the run budget ended first; not graded")
        assert cfg["State"] == "Pending" and time.time() < deadline, (
            f"the in-VPC querier never became Active: State={cfg['State']!r} "
            f"reason={cfg.get('StateReason')!r}")
        time.sleep(1)

    def dig(*queries):
        r = lam.invoke(FunctionName=fn, Payload=json.dumps(
            {"queries": [{"name": n, "type": t} for n, t in queries]}).encode())
        body = json.loads(r["Payload"].read())
        assert "FunctionError" not in r, f"the in-VPC querier failed: {body!r}"
        return body["results"]

    released = {"deleted": False, "eni_gone": False}

    def release(wait_s=None):
        if released["eni_gone"]:
            return
        if not released["deleted"]:
            _drop("function", lambda: lam.delete_function(FunctionName=fn), fn,
                  gone="ResourceNotFoundException", busy=("ResourceConflictException",))
            released["deleted"] = True
        # Lambda reclaims the ENI asynchronously, at times only after 20+ minutes, and nothing
        # reports when; the subnet's own ENI list is the observable condition, and the subnet
        # delete below cannot succeed until it is empty.
        deadline = _wait_deadline(_budget_s(ctx, 1500) if wait_s is None else wait_s)
        while True:
            enis = ec2.describe_network_interfaces(Filters=[
                {"Name": "subnet-id", "Values": [subnet_id]},
                {"Name": "description", "Values": [f"*{fn}*"]}])["NetworkInterfaces"]
            if not enis:
                released["eni_gone"] = True
                return
            if time.time() >= deadline:
                break
            time.sleep(2)
        if wait_s is None and _budget_spent(ctx):
            raise TimeoutError(f"the VPC ENI for function {fn} to leave the subnet: the run budget "
                               "ended first; not graded")
        raise RuntimeError(f"the VPC ENI for function {fn} never left subnet {subnet_id}")

    # The teardown keeps waiting for an ENI the body's wait did not see leave, up to the shared
    # teardown deadline.
    _on_cleanup(ctx, lambda: release(wait_s=_TEARDOWN_RETRY_S))
    return dig, release


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_dns(ctx, dig, queries, predicate, budget, what):
    """Poll the resolver's own answer until predicate holds.

    No API reports when a COMPLETE configuration change reaches the resolver; only the answer does.
    """
    deadline = time.time() + _budget_s(ctx, budget)
    while True:
        got = dig(*queries)
        if predicate(got):
            return got
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"{what}: the run budget ended first; not graded")
        assert time.time() < deadline, f"{what}; the last answer was {got!r}"
        time.sleep(1)


def _outbound_endpoint(ctx, r53, vpc_id, subnets, sg_id, kv):
    """An OUTBOUND Resolver endpoint with one IP per subnet; returns (id, release).

    An endpoint needs at least two IP addresses (a fixed API minimum). `release` deletes it and
    waits, minutes, for its ENIs to go; the body calls it so the VPC teardown can succeed.
    """
    assert len(subnets) >= 2, (
        f"an OUTBOUND Resolver endpoint needs IP addresses in at least 2 subnets, got {subnets!r}")
    ep_id = r53.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-ep-")[:64],
        SecurityGroupIds=[sg_id], Direction="OUTBOUND",
        IpAddresses=[{"SubnetId": s} for s in subnets],
        Tags=kv)["ResolverEndpoint"]["Id"]

    released = {"done": False}

    def release():
        if released["done"]:
            return
        released["done"] = True
        try:
            r53.delete_resolver_endpoint(ResolverEndpointId=ep_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        deadline = _wait_deadline(900)
        while time.time() < deadline:
            try:
                r53.get_resolver_endpoint(ResolverEndpointId=ep_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(2)
        raise RuntimeError(f"resolver endpoint {ep_id} never disappeared")

    _on_cleanup(ctx, release)

    # CREATING -> OPERATIONAL is real ENI provisioning; the status is the observable condition and
    # ACTION_NEEDED must never be admitted as terminal.
    seen = []
    deadline = time.time() + _budget_s(ctx, 900)
    while True:
        seen.append(r53.get_resolver_endpoint(ResolverEndpointId=ep_id)["ResolverEndpoint"])
        status = seen[-1]["Status"]
        if status == "OPERATIONAL":
            break
        if status == "CREATING" and time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"outbound endpoint {ep_id} to become OPERATIONAL: the run budget ended first; not graded")
        assert status == "CREATING" and time.time() < deadline, (
            f"the outbound endpoint {ep_id} reached {status!r} instead of OPERATIONAL: "
            f"{seen[-1].get('StatusMessage')!r}")
        time.sleep(1)
    assert seen[-1]["IpAddressCount"] == len(subnets), (
        f"the endpoint reports {seen[-1]['IpAddressCount']} IP addresses, expected one per "
        f"requested subnet ({len(subnets)})")
    return ep_id, release


def _await_gone(ctx, fn, budget, what):
    """Poll `fn()` (a Get* call) until it raises ResourceNotFoundException; return (code, message).

    Deletion is not always synchronous with the Get read reflecting it, so a single
    immediate check flakes; this bounds the wait instead of trusting an instant read.
    """
    budget = _budget_s(ctx, budget)
    deadline = time.time() + budget
    last = None
    while True:
        try:
            fn()
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last == "ResourceNotFoundException":
                return last, exc.response.get("Error", {}).get("Message", "")
            raise
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"{what} to disappear: the run budget ended first; not graded")
        assert time.time() < deadline, f"{what} still exists after {budget:.0f}s"
        time.sleep(1)


def _await_rule_assoc(ctx, r53, assoc_id, budget=420):
    """Poll a resolver rule association to COMPLETE; FAILED must not be admitted as terminal."""
    seen = []
    deadline = time.time() + _budget_s(ctx, budget)
    while True:
        seen.append(r53.get_resolver_rule_association(
            ResolverRuleAssociationId=assoc_id)["ResolverRuleAssociation"]["Status"])
        if seen[-1] == "COMPLETE":
            return seen
        if seen[-1] in ("CREATING", "OVERRIDDEN") and time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"rule association {assoc_id} to become COMPLETE: the run budget ended first; not graded")
        assert seen[-1] in ("CREATING", "OVERRIDDEN") and time.time() < deadline, (
            f"the resolver rule association reached {seen[-1]!r}, not COMPLETE; the statuses "
            f"seen were {seen[-8:]!r}")
        time.sleep(1)


def _associate_rule(ctx, r53, rule_id, vpc_id):
    """Associate a resolver rule with the VPC; return (assoc_id, release)."""
    assoc_id = r53.associate_resolver_rule(
        ResolverRuleId=rule_id, VPCId=vpc_id,
        Name=ctx.unique_name("sim2real-r53r-rra-")[:64])["ResolverRuleAssociation"]["Id"]

    released = {"done": False}

    def release():
        if released["done"]:
            return
        released["done"] = True
        try:
            r53.disassociate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceNotFoundException", "InvalidRequestException"):
                raise
        deadline = _wait_deadline(420)
        while time.time() < deadline:
            try:
                r53.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(2)
        raise RuntimeError(f"resolver rule association {assoc_id} never disappeared")

    _on_cleanup(ctx, release)
    return assoc_id, release


def _private_zone(ctx, scenario, vpc_id, labels):
    """A private hosted zone associated with the VPC, one A record per label.

    Returns (zone_name, {label: ip}); an owned namespace keeps the resolver's answer deterministic.
    """
    r53z = ctx.client("route53")
    zone = ctx.unique_name("sim2real-r53r-") + ".internal"
    zid = r53z.create_hosted_zone(
        Name=zone, VPC={"VPCRegion": ctx.region, "VPCId": vpc_id},
        CallerReference=ctx.unique_name("sim2real-cr-"),
        HostedZoneConfig={"Comment": f"sim2real {scenario}",
                          "PrivateZone": True})["HostedZone"]["Id"]
    _on_cleanup(ctx, lambda z=zid: r53z.delete_hosted_zone(Id=z))
    ips = {lab: f"10.99.88.{20 + i}" for i, lab in enumerate(labels)}
    changes = [{"Action": "CREATE", "ResourceRecordSet": {
        "Name": f"{lab}.{zone}", "Type": "A", "TTL": 60,
        "ResourceRecords": [{"Value": ip}]}} for lab, ip in ips.items()]
    change = r53z.change_resource_record_sets(
        HostedZoneId=zid, ChangeBatch={"Changes": changes})["ChangeInfo"]["Id"]
    # A hosted zone cannot be deleted while it holds non-NS/SOA records, so the record deletion is
    # registered after the zone's own cleanup and therefore runs before it.
    _on_cleanup(ctx, lambda z=zid, c=changes: r53z.change_resource_record_sets(
        HostedZoneId=z, ChangeBatch={"Changes": [
            {**ch, "Action": "DELETE"} for ch in c]}))
    r53z.get_waiter("resource_record_sets_changed").wait(
        Id=change, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return zone, ips


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c3",
    "cap:c5",
)
def run(ctx) -> None:
    """A FORWARD rule overrides a private hosted zone answer only for the domain it names while an
    unrelated domain keeps resolving, and disassociating the rule restores the original answer.
    """
    _TEARDOWN.clear()  # one run's teardown deadline never carries into the next run
    r53 = ctx.client("route53resolver")
    kv = [{"Key": "sim2real", "Value": _SCENARIO}]

    vpc_id, subnets, sg_id = _rig_vpc(ctx, _SCENARIO, 2)
    zone, ips = _private_zone(ctx, _SCENARIO, vpc_id, ["subject", "control"])
    subject, control = f"subject.{zone}", f"control.{zone}"
    dig, release_dig = _dig_in(ctx, _SCENARIO, subnets[0], sg_id)

    before = _poll_dns(
        ctx, dig, ((subject, "A"), (control, "A")),
        lambda got: bool(got[0]["answers"]) and bool(got[1]["answers"]),
        300, f"the private hosted zone {zone} never became visible to the VPC resolver")
    assert before[0]["answers"], (
        f"{subject} served no answer before any rule existed, so diverting it proves nothing: "
        f"{before[0]!r}")
    assert before[1]["answers"], (
        f"the control domain {control} served no answer before any rule existed: {before[1]!r}")

    ep_id, release_ep = _outbound_endpoint(ctx, r53, vpc_id, subnets, sg_id, kv)

    ec2 = ctx.client("ec2")
    subnet_cidr = ec2.describe_subnets(SubnetIds=[subnets[0]])["Subnets"][0]["CidrBlock"]
    blackhole = subnet_cidr.split("/")[0].rsplit(".", 1)[0] + ".250"

    rule = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-fwd-")[:64], RuleType="FORWARD",
        DomainName=subject, ResolverEndpointId=ep_id,
        TargetIps=[{"Ip": blackhole, "Port": 53}], Tags=kv)["ResolverRule"]
    rule_id = rule["Id"]
    assert rule["TargetIps"][0]["Ip"] == blackhole, (
        f"the rule did not keep the target address it was created with: {rule['TargetIps']!r}")
    def release_rule():
        # A rule still associated with the VPC refuses deletion with ResourceInUseException.
        _drop("resolver-rule", lambda: r53.delete_resolver_rule(ResolverRuleId=rule_id), rule_id,
              gone="ResourceNotFoundException", busy=("ResourceInUseException",))

    _on_cleanup(ctx, release_rule)

    assoc_id, release_assoc = _associate_rule(ctx, r53, rule_id, vpc_id)
    seen = _await_rule_assoc(ctx, r53, assoc_id)
    assert seen[-1] == "COMPLETE", f"the rule association never completed: statuses were {seen!r}"

    # The target address has nothing listening, so the rcode is not pinned: a client timeout and a
    # resolver SERVFAIL both present as no answers. A control query that timed out is retried.
    diverted = _poll_dns(
        ctx, dig, ((subject, "A"), (control, "A")),
        lambda got: not got[0]["answers"] and got[1]["rcode"] != "TIMEOUT",
        300, f"the FORWARD rule never diverted {subject} away from the resolver's own answer")
    assert diverted[1]["answers"], (
        f"the control domain {control} stopped resolving too, so the rule is not scoped to the "
        f"domain it names: {diverted[1]!r}")

    # A different operation than the mutation confirms the association is the one this check made.
    listed = [a for a in r53.list_resolver_rule_associations()["ResolverRuleAssociations"]
              if a["Id"] == assoc_id]
    assert len(listed) == 1, (
        f"expected exactly one association {assoc_id} in ListResolverRuleAssociations, found "
        f"{len(listed)}")
    assert listed[0]["VPCId"] == vpc_id and listed[0]["ResolverRuleId"] == rule_id, (
        f"the listed association does not match what was created: {listed[0]!r}")

    release_assoc()
    restored = _poll_dns(
        ctx, dig, ((subject, "A"),),
        lambda got: bool(got[0]["answers"]),
        300, f"disassociating the rule never restored the resolver's own answer for {subject}")
    assert restored[0]["rcode"] == "NOERROR", (
        f"{subject} came back with the wrong rcode after the rule was withdrawn: "
        f"{restored[0]!r}")
    assert restored[0]["answers"][0]["rdata"] == ips["subject"], (
        f"{subject} came back with an address its zone does not hold: {restored[0]!r}")

    release_dig()

    # DeleteResolverEndpoint refuses (RSLVR-00600) while any rule still names it, so the rule is
    # deleted first; after each delete a read must report the not-found code.
    release_rule()
    rule_gone, rule_message = _await_gone(
        ctx, lambda: r53.get_resolver_rule(ResolverRuleId=rule_id), 60, f"resolver rule {rule_id}")
    assert rule_gone == "ResourceNotFoundException", (
        f"GetResolverRule after delete raised the wrong code: {rule_gone!r}")
    expected = f'[RSLVR-00703] Resolver rule with ID "{rule_id}" does not exist.'
    assert rule_message == expected, f"expected message {expected!r}, got {rule_message!r}"

    release_ep()
    ep_gone, ep_message = _await_gone(
        ctx, lambda: r53.get_resolver_endpoint(ResolverEndpointId=ep_id), 300, f"resolver endpoint {ep_id}")
    assert ep_gone == "ResourceNotFoundException", (
        f"GetResolverEndpoint after delete raised the wrong code: {ep_gone!r}")
    expected = f'[RSLVR-00501] Resolver endpoint with ID "{ep_id}" does not exist.'
    assert ep_message == expected, f"expected message {expected!r}, got {ep_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
