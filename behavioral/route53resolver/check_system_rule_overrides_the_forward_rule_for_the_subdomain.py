"""system-rule-overrides-the-forward-rule-for-the-subdomain."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "system-rule-overrides-the-forward-rule-for-the-subdomain"
GROUP = "resolver-rule"
SERVICES = ["route53resolver"]

# Behavior under test:
#   1. A FORWARD rule whose only TargetIps entry is an in-VPC address with nothing listening
#      makes the matched name stop resolving -- i.e. the answer section comes back EMPTY. The
#      rcode is deliberately NOT asserted, because SERVFAIL and a socket TIMEOUT are both
#      valid and either satisfies the property.
#   2. A FORWARD rule on `example.com` also matches `www.example.com` (subdomain matching).
#   3. A SYSTEM rule on `www.example.com` restores normal resolution for that name while the
#      apex stays forwarded -- the documented precedence, and the whole point of the check.
#   4. Both `example.com` and `www.example.com` resolve publicly from a private subnet with no
#      internet gateway (the Amazon-provided resolver is reachable at 169.254.169.253 and
#      resolves public names whenever EnableDnsSupport is on).
#
# DeleteResolverEndpoint refuses (InvalidRequestException / RSLVR-00600) while any resolver rule
# still names the endpoint via ResolverEndpointId, even one disassociated from every VPC, so the
# body deletes the FORWARD rule explicitly before the endpoint.

_SCENARIO = "r53r-system-overrides-forward"

_CIDR = "10.60.0.0/16"
_BASE = _CIDR.split("/")[0].rsplit(".", 2)[0]


# The in-use refusals of the deletes below: VPC/subnet ENIs draining, an IAM role with a policy
# attached, a Lambda function mid-update, a resolver rule still associated.
_IN_USE = ("DependencyViolation", "DeleteConflict", "ResourceConflictException",
           "ResourceInUseException")


def _drop(what, fn, ident):
    """Bounded delete: done on success or a not-found answer, an in-use refusal is retried every
    2 s, and anything else or a timeout raises."""
    deadline = time.time() + 300
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            # Already gone is success. `InvalidChangeBatch` is Route 53's answer when a record
            # set being deleted is not there, and `NoSuch*` is its answer for a missing zone.
            if "NotFound" in code or "NoSuch" in code or code == "InvalidChangeBatch":
                return
            if code not in _IN_USE or time.time() >= deadline:
                raise RuntimeError(f"{what} {ident} was not deleted: {exc}") from exc
        time.sleep(2)


def _rig_vpc(ctx, scenario, subnet_count):
    """Create a DEDICATED VPC with `subnet_count` subnets in distinct AZs; return ids.

    An account's default VPC can have fewer than two subnets in distinct AZs, so the VPC is created
    here, and a quota refusal surfaces as a FAIL naming the real error code instead of being
    swallowed into a fallback.
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
    ctx.on_cleanup(lambda v=vpc_id: _drop("vpc", lambda: ec2.delete_vpc(VpcId=v), v))
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
        ctx.on_cleanup(lambda x=sid: _drop(
            "subnet", lambda: ec2.delete_subnet(SubnetId=x), x))
    groups = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]
    assert groups, (
        f"the VPC {vpc_id} this check just created reports no default security group, so nothing "
        f"can be placed in it")
    return vpc_id, subnets, groups[0]["GroupId"]


# A DNS resolver in pure stdlib, deployed as a Lambda function with a VPC ENI so its queries
# originate INSIDE the VPC. Route 53 Resolver's data plane answers in-VPC sources only, so this
# fixture is the only way to observe it at all -- nothing the harness itself can call ever sees a
# DNS answer. It parses the wire format structurally and returns the rcode plus every answer
# record's name/ttl/type/rdata, instead of scraping a text tool's output. Byte-identical to the
# querier already blessed in behavioral/ec2__lambda__logs__route53resolver/, deliberately: a
# second, subtly different parser would make the two suites incomparable.
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

    `release` deletes the function and WAITS for its service-managed ENI to leave the subnet.
    It is called from the body, not only from cleanup: the default cleanup budget is 60s and a
    Lambda VPC ENI can take minutes to be reclaimed, so leaving it to teardown means the subnet
    and VPC deletes are cut off and the run leaks a VPC.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    cwl = ctx.client("logs")
    kv = [{"Key": "sim2real", "Value": scenario}]

    role = ctx.unique_name("sim2real-r53r-dnsfn-")
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=_TRUST,
                               Description="sim2real in-VPC DNS querier", Tags=kv)["Role"]["Arn"]
    ctx.on_cleanup(lambda n=role: _drop(
        "role", lambda: iam.delete_role(RoleName=n), n))
    iam.attach_role_policy(RoleName=role, PolicyArn=_VPC_EXEC)
    ctx.on_cleanup(lambda n=role: _drop(
        "role-policy", lambda: iam.detach_role_policy(RoleName=n, PolicyArn=_VPC_EXEC), n))

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
            time.sleep(5)

    def _drop_log_group(g=f"/aws/lambda/{fn}"):
        # Lambda -- not this check -- creates /aws/lambda/<fn> on the first invoke.
        try:
            cwl.delete_log_group(logGroupName=g)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_drop_log_group)

    # The function cannot be invoked until its VPC ENI exists; State is the observable condition.
    deadline = time.time() + 600
    while True:
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Active":
            break
        assert cfg["State"] == "Pending" and time.time() < deadline, (
            f"the in-VPC querier never became Active: State={cfg['State']!r} "
            f"reason={cfg.get('StateReason')!r}")
        time.sleep(5)

    def dig(*queries):
        r = lam.invoke(FunctionName=fn, Payload=json.dumps(
            {"queries": [{"name": n, "type": t} for n, t in queries]}).encode())
        body = json.loads(r["Payload"].read())
        assert "FunctionError" not in r, f"the in-VPC querier failed: {body!r}"
        return body["results"]

    released = {"deleted": False, "eni_gone": False}

    def release(wait_s=1500.0):
        if released["eni_gone"]:
            return
        if not released["deleted"]:
            _drop("function", lambda: lam.delete_function(FunctionName=fn), fn)
            released["deleted"] = True
        if not wait_s:
            return
        # Lambda reclaims the ENI asynchronously, at times only after 20 minutes, and nothing
        # reports when; the subnet's own ENI list is the observable condition, and the subnet
        # delete below cannot succeed until it is empty.
        left = ctx.time_left()
        deadline = time.time() + (wait_s if left is None else max(1.0, min(wait_s, left - 30.0)))
        while True:
            enis = ec2.describe_network_interfaces(Filters=[
                {"Name": "subnet-id", "Values": [subnet_id]},
                {"Name": "description", "Values": [f"*{fn}*"]}])["NetworkInterfaces"]
            if not enis:
                released["eni_gone"] = True
                return
            if time.time() >= deadline:
                raise RuntimeError(f"the VPC ENI for function {fn} never left subnet {subnet_id}")
            time.sleep(2)

    # The teardown keeps waiting for an ENI the body's wait did not see leave.
    ctx.on_cleanup(lambda: release(wait_s=600.0))
    return dig, release


def _poll_dns(dig, queries, predicate, budget, what):
    """Poll the resolver's OWN ANSWER until predicate holds.

    A configuration change reaching COMPLETE is a control-plane fact; whether the resolver has
    started applying it is only observable in the answer, and no API reports that. So the answer is
    the condition -- never a fixed sleep sized to make this pass.
    """
    deadline = time.time() + budget
    while True:
        got = dig(*queries)
        if predicate(got):
            return got
        assert time.time() < deadline, f"{what}; the last answer was {got!r}"
        time.sleep(5)


def _outbound_endpoint(ctx, r53, vpc_id, subnets, sg_id, kv):
    """An OUTBOUND Resolver endpoint with one IP per subnet; returns (id, release).

    A Resolver endpoint requires at least two IP addresses and each IP is one elastic network
    interface, so two subnets in distinct AZs is the minimum shape -- that is a fixed API constant,
    not an account-adjustable quota, which is why it is pinned here.

    `release` deletes the endpoint and waits for it to be gone. It is called from the BODY, not
    only from cleanup: endpoint deletion tears down ENIs and takes minutes, and the default 60s
    cleanup budget would be cut off mid-flight -- which passes while leaking the VPC.
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
        deadline = time.time() + 900
        while time.time() < deadline:
            try:
                r53.get_resolver_endpoint(ResolverEndpointId=ep_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(10)
        raise RuntimeError(f"resolver endpoint {ep_id} never disappeared")

    ctx.on_cleanup(release)

    # CREATING -> OPERATIONAL is real ENI provisioning; the status is the observable condition and
    # ACTION_NEEDED must never be admitted as terminal.
    seen = []
    deadline = time.time() + 900
    while True:
        seen.append(r53.get_resolver_endpoint(ResolverEndpointId=ep_id)["ResolverEndpoint"])
        status = seen[-1]["Status"]
        if status == "OPERATIONAL":
            break
        assert status == "CREATING" and time.time() < deadline, (
            f"the outbound endpoint {ep_id} reached {status!r} instead of OPERATIONAL: "
            f"{seen[-1].get('StatusMessage')!r}")
        time.sleep(2)
    assert seen[-1]["IpAddressCount"] == len(subnets), (
        f"the endpoint reports {seen[-1]['IpAddressCount']} IP addresses, expected one per "
        f"requested subnet ({len(subnets)})")
    return ep_id, release


def _await_rule_assoc(r53, assoc_id, budget=420):
    """Poll a resolver rule association to COMPLETE; FAILED must not be admitted as terminal."""
    seen = []
    deadline = time.time() + budget
    while True:
        seen.append(r53.get_resolver_rule_association(
            ResolverRuleAssociationId=assoc_id)["ResolverRuleAssociation"]["Status"])
        if seen[-1] == "COMPLETE":
            return seen
        assert seen[-1] in ("CREATING", "OVERRIDDEN") and time.time() < deadline, (
            f"the resolver rule association reached {seen[-1]!r}, not COMPLETE; the statuses "
            f"seen were {seen[-8:]!r}")
        time.sleep(5)


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
        deadline = time.time() + 420
        while time.time() < deadline:
            try:
                r53.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(5)
        raise RuntimeError(f"resolver rule association {assoc_id} never disappeared")

    ctx.on_cleanup(release)
    return assoc_id, release


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
    """A SYSTEM rule for a subdomain overrides the FORWARD rule that covers its parent domain. Every API
    response for the two rules is identical either way, so the check reads the answers real queries
    get inside the VPC, with the parent and the subdomain queried in the same batch."""
    r53 = ctx.client("route53resolver")
    kv = [{"Key": "sim2real", "Value": _SCENARIO}]
    parent, child = "example.com", "www.example.com"

    vpc_id, subnets, sg_id = _rig_vpc(ctx, _SCENARIO, 2)
    dig, release_dig = _dig_in(ctx, _SCENARIO, subnets[0], sg_id)

    # BASELINE / POSITIVE CONTROL. Without this, "the subdomain resolves" below is
    # indistinguishable from "nothing was ever forwarded".
    before = dig((parent, "A"), (child, "A"))
    assert before[0]["answers"], (
        f"{parent} served no answer from inside the VPC before any rule existed, so diverting it "
        f"below would prove nothing: {before[0]!r}")
    assert before[1]["answers"], (
        f"{child} served no answer from inside the VPC before any rule existed, so restoring it "
        f"below would prove nothing: {before[1]!r}")

    ep_id, release_ep = _outbound_endpoint(ctx, r53, vpc_id, subnets, sg_id, kv)

    # The forward target is an address inside this VPC with nothing listening on it, derived from
    # the subnet CIDR this check created rather than pinned: the point is that the resolver stops
    # answering from its own recursive path, not where the query lands.
    ec2 = ctx.client("ec2")
    subnet_cidr = ec2.describe_subnets(SubnetIds=[subnets[0]])["Subnets"][0]["CidrBlock"]
    blackhole = subnet_cidr.split("/")[0].rsplit(".", 1)[0] + ".250"

    fwd_id = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-fwd-")[:64], RuleType="FORWARD",
        DomainName=parent, ResolverEndpointId=ep_id,
        TargetIps=[{"Ip": blackhole, "Port": 53}], Tags=kv)["ResolverRule"]["Id"]

    # A resolver rule that still names `ep_id` via ResolverEndpointId blocks
    # DeleteResolverEndpoint with InvalidRequestException/RSLVR-00600, even once its VPC
    # association is gone -- measured on real AWS. So this must be released before release_ep(),
    # not left to on_cleanup ordering, and idempotent since both call it.
    released_fwd_rule = {"done": False}

    def release_fwd_rule():
        if released_fwd_rule["done"]:
            return
        _drop("resolver-rule", lambda: r53.delete_resolver_rule(ResolverRuleId=fwd_id), fwd_id)
        released_fwd_rule["done"] = True

    ctx.on_cleanup(release_fwd_rule)
    fwd_assoc, release_fwd_assoc = _associate_rule(ctx, r53, fwd_id, vpc_id)
    fwd_seen = _await_rule_assoc(r53, fwd_assoc)
    assert fwd_seen[-1] == "COMPLETE", (
        f"the FORWARD rule association never completed: statuses were {fwd_seen!r}")

    # THE BARRIER. The poll waits only on the PARENT so that the claim about the SUBDOMAIN is a
    # real assertion rather than a restatement of the poll's own exit condition: a FORWARD rule on
    # example.com is documented to match www.example.com too, and that is what must be proven
    # before the SYSTEM rule below can be said to have overturned anything.
    forwarded = _poll_dns(
        dig, ((parent, "A"), (child, "A")),
        lambda got: not got[0]["answers"],
        300,
        f"the FORWARD rule for {parent} never diverted {parent} away from the resolver's own "
        f"recursive answer")
    assert not forwarded[1]["answers"], (
        f"{child} kept resolving recursively while its parent {parent} was forwarded, so the "
        f"FORWARD rule is not matching subdomains: {forwarded[1]!r}")

    sys_id = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-sys-")[:64], RuleType="SYSTEM",
        DomainName=child, Tags=kv)["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda x=sys_id: _drop(
        "resolver-rule", lambda: r53.delete_resolver_rule(ResolverRuleId=x), x))
    sys_assoc, release_sys_assoc = _associate_rule(ctx, r53, sys_id, vpc_id)
    sys_seen = _await_rule_assoc(r53, sys_assoc)
    assert sys_seen[-1] == "COMPLETE", (
        f"the SYSTEM rule association never completed: statuses were {sys_seen!r}")

    # THE PROPERTY. One batch, two names: the more specific SYSTEM rule wins for the subdomain
    # while the FORWARD rule still owns the parent. An emulator that keeps a flat rule map and
    # takes the first or the last match gets exactly one of these two wrong.
    overridden = _poll_dns(
        dig, ((parent, "A"), (child, "A")),
        lambda got: bool(got[1]["answers"]),
        300,
        f"the SYSTEM rule for {child} never overrode the FORWARD rule for {parent}")
    assert overridden[1]["rcode"] == "NOERROR", (
        f"{child} came back with the wrong rcode once the SYSTEM rule applied: "
        f"{overridden[1]!r}")
    assert not overridden[0]["answers"], (
        f"the SYSTEM rule for {child} also un-forwarded its parent {parent}, so precedence is "
        f"not scoped to the subdomain: {overridden[0]!r}")

    # RESTORE THE ONE BROKEN THING. Removing only the SYSTEM rule must put the subdomain back
    # under its parent's FORWARD rule. Without this leg, a target that never forwarded anything
    # at all would have scored green on the batch above.
    # The bounded poll IS this leg's assertion: it raises with the last answer if the subdomain
    # keeps resolving, which would mean the batch above was not caused by the SYSTEM rule.
    release_sys_assoc()
    relapsed = _poll_dns(
        dig, ((child, "A"), (parent, "A")),
        lambda got: not got[0]["answers"],
        300,
        f"disassociating the SYSTEM rule never returned {child} to its parent's FORWARD rule, so "
        f"the override observed above was not caused by that rule")
    assert not relapsed[1]["answers"], (
        f"the parent {parent} started resolving again when the SYSTEM rule was withdrawn, so the "
        f"FORWARD rule stopped applying at the same moment and neither arm is attributable: "
        f"{relapsed[1]!r}")

    # Teardown of the slow resources happens here, inside the body budget. The function is deleted
    # first so its ENI reclaim runs while the rules and the endpoint are torn down.
    release_dig(wait_s=0)
    release_fwd_assoc()
    release_fwd_rule()
    release_ep()
    release_dig()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
