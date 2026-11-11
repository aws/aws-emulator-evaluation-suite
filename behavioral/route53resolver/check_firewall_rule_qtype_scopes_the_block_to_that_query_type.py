"""firewall-rule-qtype-scopes-the-block-to-that-query-type."""
from __future__ import annotations

import io
import json
import random
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-rule-qtype-scopes-the-block-to-that-query-type"
GROUP = "firewall-data-plane"
SERVICES = ["route53resolver"]

# The flip leg deletes the AAAA rule and creates an A rule rather than calling UpdateFirewallRule
# with a new Qtype: a rule's identity in a group is (FirewallDomainListId, Qtype), which makes it
# ambiguous whether UpdateFirewallRule(..., Qtype=X) selects a rule or assigns one.

_SCENARIO = "r53r-qtype-scoped-block"

# ===== helpers (self-contained) =====

_CIDR = "10.63.0.0/16"
_BASE = _CIDR.split("/")[0].rsplit(".", 2)[0]


def _drop(what, fn, ident):
    """Bounded delete that tolerates a dependency still draining and reports a LEAK loudly.

    A cut-off teardown PASSES while leaking, and leaked VPCs exhaust the account's VPC quota -- so
    the failure mode is announced on stdout with the id rather than swallowed.
    """
    deadline = time.time() + 300
    last = None
    while time.time() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            # Already gone is success. `InvalidChangeBatch` is Route 53's answer when a record
            # set being deleted is not there, and `NoSuch*` is its answer for a missing zone.
            if "NotFound" in code or "NoSuch" in code or code == "InvalidChangeBatch":
                return
            last = exc
            time.sleep(6)
    raise RuntimeError(f"{what} {ident} was not deleted: {last}")


def _rig_vpc(ctx, scenario, subnet_count):
    """Create a DEDICATED VPC with `subnet_count` subnets in distinct AZs; return ids.

    The check never depends on an ambient default VPC, which may lack two subnets in distinct
    AZs. So the VPC is created here, and a quota refusal surfaces as a FAIL naming the real error
    code instead of being swallowed into a fallback.
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
        ctx.on_cleanup(lambda x=sid: _drop("subnet", lambda: ec2.delete_subnet(SubnetId=x), x))
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
    ctx.on_cleanup(lambda n=role: _drop("role", lambda: iam.delete_role(RoleName=n), n))
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
        # Lambda -- not this check -- creates /aws/lambda/<fn> on the first invoke, so it is a
        # child nothing registers by default and a tag-based cleanup cannot match.
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

    released = {"done": False}

    def release():
        if released["done"]:
            return
        released["done"] = True
        _drop("function", lambda: lam.delete_function(FunctionName=fn), fn)
        # Lambda reclaims the ENI asynchronously and nothing reports when; the subnet's own ENI
        # list is the observable condition, and the subnet delete below cannot succeed until it
        # is empty.
        deadline = time.time() + 900
        while time.time() < deadline:
            enis = ec2.describe_network_interfaces(Filters=[
                {"Name": "subnet-id", "Values": [subnet_id]},
                {"Name": "description", "Values": [f"*{fn}*"]}])["NetworkInterfaces"]
            if not enis:
                return
            time.sleep(15)
        raise RuntimeError(f"the VPC ENI for function {fn} never left subnet {subnet_id}")

    ctx.on_cleanup(release)
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


def _await_fw_assoc(r53, assoc_id, budget=420):
    """Statuses seen while a firewall rule group association converges on COMPLETE.

    Bounded and asserted rather than slept through: an emulator that parks the association in
    UPDATING for ever is exactly the defect this poll is here to catch.
    """
    seen = []
    deadline = time.time() + budget
    while True:
        seen.append(r53.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id)["FirewallRuleGroupAssociation"]["Status"])
        if seen[-1] == "COMPLETE":
            return seen
        assert time.time() < deadline, (
            f"the firewall rule group association never left {seen[-1]!r} -- the statuses seen "
            f"were {seen[-8:]!r}")
        time.sleep(5)


def _associate_fw(ctx, r53, grp_id, vpc_id, kv):
    """Associate the rule group with the VPC at a FREE association priority.

    Association priority is unique per VPC, so a hardcoded literal collides with whatever else in
    a shared account already holds that slot -- a failure that has nothing to do with the
    rule being graded. The retry picks another number instead of reporting a fidelity problem.
    """
    last = None
    for _ in range(8):
        try:
            return r53.associate_firewall_rule_group(
                CreatorRequestId=ctx.unique_name("sim2real-cr-"), FirewallRuleGroupId=grp_id,
                VpcId=vpc_id, Priority=random.randrange(1000, 9000),
                Name=ctx.unique_name("sim2real-r53r-fga-"), Tags=kv
            )["FirewallRuleGroupAssociation"]["Id"]
        except ClientError as exc:
            last = exc
            time.sleep(3)
    raise AssertionError(
        f"could not associate the rule group with {vpc_id} at any priority: {last}")


def _fw_dropper(r53, assoc_id):
    """Disassociate the rule group AND wait for it to be gone.

    The wait is load-bearing: disassociation is asynchronous, and delete_firewall_rule_group is
    refused while the association exists.
    """
    def _drop_assoc():
        try:
            r53.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        deadline = time.time() + 420
        while time.time() < deadline:
            try:
                r53.get_firewall_rule_group_association(
                    FirewallRuleGroupAssociationId=assoc_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(5)
        print(f"firewall rule group association {assoc_id} never disappeared")
    return _drop_assoc


def _blocklist(ctx, r53, kv, domains):
    """A firewall domain list holding `domains`, and an empty rule group to put rules in."""
    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-fdl-"), Tags=kv)["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: _drop(
        "domain-list", lambda: r53.delete_firewall_domain_list(FirewallDomainListId=x), x))
    r53.update_firewall_domains(FirewallDomainListId=dl_id, Operation="ADD", Domains=domains)
    grp_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-frg-"), Tags=kv)["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=grp_id: _drop(
        "rule-group", lambda: r53.delete_firewall_rule_group(FirewallRuleGroupId=x), x))
    return dl_id, grp_id


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c3",
    "cap:c5",
)

def run(ctx) -> None:
    """A Qtype-scoped BLOCK rule blocks that query type and only that query type: queried in one
    batch, the scoped type is refused while the other type for the same domain still answers.
    """
    r53 = ctx.client("route53resolver")
    kv = [{"Key": "sim2real", "Value": _SCENARIO}]
    target, control = "example.com", "example.org"

    vpc_id, subnets, sg_id = _rig_vpc(ctx, _SCENARIO, 1)
    dig, release_dig = _dig_in(ctx, _SCENARIO, subnets[0], sg_id)

    before = dig((target, "A"), (target, "AAAA"), (control, "A"))
    assert before[0]["rcode"] == "NOERROR", (
        f"an A query for {target} did not succeed before any rule existed, so blocking one query "
        f"type below would prove nothing: {before[0]!r}")
    assert before[1]["rcode"] == "NOERROR", (
        f"an AAAA query for {target} did not succeed before any rule existed: {before[1]!r}")
    assert before[2]["answers"], (
        f"the control domain {control} served no answer before any rule existed: {before[2]!r}")

    dl_id, grp_id = _blocklist(ctx, r53, kv, [target])

    def _rule(qtype):
        r53.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-cr-"), FirewallRuleGroupId=grp_id,
            FirewallDomainListId=dl_id, Priority=100, Action="BLOCK",
            BlockResponse="NXDOMAIN", Qtype=qtype,
            Name=ctx.unique_name("sim2real-r53r-fr-"))

    def _unrule(qtype):
        r53.delete_firewall_rule(FirewallRuleGroupId=grp_id, FirewallDomainListId=dl_id,
                                 Qtype=qtype)

    _rule("AAAA")
    ctx.on_cleanup(lambda: _drop("firewall-rule", lambda: _unrule("AAAA"), f"{grp_id}/AAAA"))

    assoc_id = _associate_fw(ctx, r53, grp_id, vpc_id, kv)
    drop_assoc = _fw_dropper(r53, assoc_id)
    ctx.on_cleanup(drop_assoc)
    seen = _await_fw_assoc(r53, assoc_id)
    assert seen[-1] == "COMPLETE", f"the association never completed: statuses were {seen!r}"

    scoped = _poll_dns(
        dig, ((target, "A"), (target, "AAAA"), (control, "A")),
        lambda got: got[1]["rcode"] == "NXDOMAIN",
        240, f"the Qtype=AAAA BLOCK rule never stopped AAAA resolution of {target}")
    assert scoped[1]["answers"] == [], (
        f"the blocked AAAA query still carried answer records: {scoped[1]!r}")
    assert scoped[0]["rcode"] == "NOERROR", (
        f"the A query for {target} was blocked too, so Qtype does not scope the block: "
        f"expected NOERROR, got {scoped[0]!r}")
    assert scoped[2]["answers"], (
        f"the control domain {control} stopped resolving, so the block is not scoped to the "
        f"domain list either: {scoped[2]!r}")

    # THE FLIP. Same domain list, same group, same priority, the other query type. If the target
    # blocks by name rather than by (name, qtype) both arms look identical in both directions;
    # only a target that honours Qtype swaps which one refuses.
    _unrule("AAAA")
    _rule("A")
    ctx.on_cleanup(lambda: _drop("firewall-rule", lambda: _unrule("A"), f"{grp_id}/A"))
    flipped = _poll_dns(
        dig, ((target, "A"), (target, "AAAA"), (control, "A")),
        lambda got: got[0]["rcode"] == "NXDOMAIN",
        240, f"replacing the rule with Qtype=A never moved the block onto A queries for {target}")
    assert flipped[0]["answers"] == [], (
        f"the blocked A query still carried answer records: {flipped[0]!r}")
    assert flipped[1]["rcode"] == "NOERROR", (
        f"AAAA stayed blocked after the rule moved to Qtype=A, so the block is not keyed on the "
        f"query type: expected NOERROR, got {flipped[1]!r}")
    assert flipped[2]["answers"], (
        f"the control domain {control} stopped resolving after the flip: {flipped[2]!r}")

    drop_assoc()
    release_dig()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
