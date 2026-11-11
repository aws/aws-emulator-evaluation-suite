"""firewall-rule-group-association-priority-decides-the-live-answer."""
from __future__ import annotations

import io
import json
import random
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-rule-group-association-priority-decides-the-live-answer"
GROUP = "firewall-data-plane"
SERVICES = ["route53resolver"]

_SCENARIO = "r53r-group-association-priority"

_CIDR = "10.66.0.0/16"
_BASE = _CIDR.split("/")[0].rsplit(".", 2)[0]


def _drop(what, fn, ident):
    """Bounded delete that tolerates a dependency still draining; a delete that never succeeds
    is reported with its id rather than swallowed."""
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
        # Lambda, not this check, creates /aws/lambda/<fn> on the first invoke, untagged.
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
    """Poll the resolver's own answer until predicate holds.

    No API reports when a COMPLETE configuration change reaches the resolver; only the answer does.
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

    Bounded and asserted, so an association parked in UPDATING forever fails the check.
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
    """Associate the rule group with the VPC at a free association priority.

    Association priority is unique per VPC, so a collision retries with another random number.
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
        raise RuntimeError(f"firewall rule group association {assoc_id} never disappeared")
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
    ctx.on_cleanup(lambda z=zid: r53z.delete_hosted_zone(Id=z))
    ips = {lab: f"10.99.88.{20 + i}" for i, lab in enumerate(labels)}
    changes = [{"Action": "CREATE", "ResourceRecordSet": {
        "Name": f"{lab}.{zone}", "Type": "A", "TTL": 60,
        "ResourceRecords": [{"Value": ip}]}} for lab, ip in ips.items()]
    change = r53z.change_resource_record_sets(
        HostedZoneId=zid, ChangeBatch={"Changes": changes})["ChangeInfo"]["Id"]
    # A hosted zone cannot be deleted while it holds non-NS/SOA records, so the record deletion is
    # registered after the zone's own cleanup and therefore runs before it.
    ctx.on_cleanup(lambda z=zid, c=changes: r53z.change_resource_record_sets(
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
    """With an ALLOW group and a BLOCK group on one VPC, the lower association Priority decides the
    live DNS answer, and swapping the priorities in place flips it.
    """
    r53 = ctx.client("route53resolver")
    kv = [{"Key": "sim2real", "Value": _SCENARIO}]

    vpc_id, subnets, sg_id = _rig_vpc(ctx, _SCENARIO, 1)
    zone, _ips = _private_zone(ctx, _SCENARIO, vpc_id, ["target", "control"])
    target, control = f"target.{zone}", f"control.{zone}"
    dig, release_dig = _dig_in(ctx, _SCENARIO, subnets[0], sg_id)

    before = _poll_dns(
        dig, ((target, "A"), (control, "A")),
        lambda got: bool(got[0]["answers"]) and bool(got[1]["answers"]),
        300, f"the private hosted zone {zone} never became visible to the VPC resolver")
    assert before[0]["answers"], (
        f"{target} served no answer before any rule existed, so neither arm below would prove "
        f"anything: {before[0]!r}")
    assert before[1]["answers"], (
        f"the control domain {control} served no answer before any rule existed: {before[1]!r}")

    # Two groups, one domain list each, opposite verdicts on the same name.
    dl_allow, grp_allow = _blocklist(ctx, r53, kv, [target])
    dl_block, grp_block = _blocklist(ctx, r53, kv, [target])
    r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"), FirewallRuleGroupId=grp_allow,
        FirewallDomainListId=dl_allow, Priority=100, Action="ALLOW",
        Name=ctx.unique_name("sim2real-r53r-fra-"))
    ctx.on_cleanup(lambda g=grp_allow, d=dl_allow: _drop(
        "firewall-rule",
        lambda: r53.delete_firewall_rule(FirewallRuleGroupId=g, FirewallDomainListId=d),
        f"{g}/{d}"))
    r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"), FirewallRuleGroupId=grp_block,
        FirewallDomainListId=dl_block, Priority=100, Action="BLOCK", BlockResponse="NXDOMAIN",
        Name=ctx.unique_name("sim2real-r53r-frb-"))
    ctx.on_cleanup(lambda g=grp_block, d=dl_block: _drop(
        "firewall-rule",
        lambda: r53.delete_firewall_rule(FirewallRuleGroupId=g, FirewallDomainListId=d),
        f"{g}/{d}"))

    a_assoc = _associate_fw(ctx, r53, grp_allow, vpc_id, kv)
    ctx.on_cleanup(_fw_dropper(r53, a_assoc))
    b_assoc = _associate_fw(ctx, r53, grp_block, vpc_id, kv)
    drop_b = _fw_dropper(r53, b_assoc)
    ctx.on_cleanup(drop_b)
    for aid in (a_assoc, b_assoc):
        s = _await_fw_assoc(r53, aid)
        assert s[-1] == "COMPLETE", f"association {aid} never completed: statuses were {s!r}"

    def prio(assoc_id):
        return r53.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id)["FirewallRuleGroupAssociation"]["Priority"]

    def _reorder(first_assoc, second_assoc):
        """Give `first_assoc` the lower of the two priorities currently in play.

        Only their order matters, so the numbers are read back rather than pinned.
        """
        lo, hi = sorted((prio(first_assoc), prio(second_assoc)))
        if prio(first_assoc) == lo:
            return lo, hi
        # Park one out of the way first: priorities are unique per VPC, so a direct swap would
        # transiently collide.
        park = hi + 1
        r53.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=second_assoc, Priority=park)
        r53.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=first_assoc, Priority=lo)
        r53.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=second_assoc, Priority=hi)
        for aid in (first_assoc, second_assoc):
            s = _await_fw_assoc(r53, aid)
            assert s[-1] == "COMPLETE", (
                f"association {aid} never completed after re-ordering: statuses were {s!r}")
        return lo, hi

    # ALLOW first: the BLOCK group is still associated and still names the domain.
    lo, hi = _reorder(a_assoc, b_assoc)
    assert prio(a_assoc) < prio(b_assoc), (
        f"the ALLOW group is not ordered first: ALLOW={prio(a_assoc)} BLOCK={prio(b_assoc)}")
    allowed = _poll_dns(
        dig, ((target, "A"), (control, "A")),
        lambda got: bool(got[0]["answers"]),
        300,
        f"with the ALLOW group at priority {lo} ahead of the BLOCK group at {hi}, {target} never "
        f"resolved")
    assert allowed[0]["rcode"] == "NOERROR", (
        f"{target} came back with the wrong rcode while the ALLOW group was first: "
        f"{allowed[0]!r}")
    assert allowed[1]["answers"], (
        f"the control domain {control} stopped resolving: {allowed[1]!r}")

    # BLOCK first: nothing changes except the two numbers.
    lo2, hi2 = _reorder(b_assoc, a_assoc)
    assert prio(b_assoc) < prio(a_assoc), (
        f"the BLOCK group is not ordered first: BLOCK={prio(b_assoc)} ALLOW={prio(a_assoc)}")
    blocked = _poll_dns(
        dig, ((target, "A"), (control, "A")),
        lambda got: got[0]["rcode"] == "NXDOMAIN",
        300,
        f"moving the BLOCK group to priority {lo2} ahead of the ALLOW group at {hi2} never "
        f"changed the live answer for {target}")
    assert blocked[0]["answers"] == [], (
        f"{target} was refused but still carried answer records: {blocked[0]!r}")
    assert blocked[1]["answers"], (
        f"the control domain {control} stopped resolving once the BLOCK group moved first, so "
        f"the block is not scoped to the domain list: {blocked[1]!r}")

    drop_b()
    release_dig()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
