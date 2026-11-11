"""dns-firewall-block-rule-actually-blocks-resolution-inside-the-vpc."""
from __future__ import annotations

import io
import json
import random
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dns-firewall-block-rule-actually-blocks-resolution-inside-the-vpc"
GROUP = 'firewall-data-plane'
SERVICES = ['ec2', 'lambda', 'logs', 'route53resolver']

_SCENARIO = 'r53r-firewall-block'

# A DNS resolver in pure stdlib, deployed as a Lambda function with a VPC ENI so its queries
# originate INSIDE the VPC. Route 53 Resolver's data plane answers in-VPC sources only, so this
# fixture is the only way to observe it at all -- nothing the harness itself can call ever sees a
# DNS answer. It parses the wire format structurally and returns the rcode plus every answer
# record's name/ttl/type/rdata, instead of scraping a text tool's output.
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


_NET_CIDR = "10.91.0.0/16"
# Lambda refuses a VpcConfig subnet in this zone, so the querier's subnet never lands there.
_NO_LAMBDA_ZONES = {"use1-az3"}


def _own_network(ctx, made, scenario):
    """Create the VPC the querier lives in: one subnet and the VPC's own default security group.

    DNS support and DNS hostnames are both on, which Route 53 Resolver and private hosted zones
    require. The VPC and subnet are removed by the LAST cleanup to run, after every resolver
    association on the VPC is undone. The Lambda ENI that holds the subnet is drained inside
    run() first (see _drain_querier), because the engine bounds the whole cleanup chain and the
    ENI release alone can outlast it.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"sim2real-{scenario}-")
    tags = [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": scenario}]
    vpc_id = ec2.create_vpc(CidrBlock=_NET_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]
    made["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _delete_network(ec2, made))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    zones = sorted(
        (z["ZoneId"], z["ZoneName"]) for z in ec2.describe_availability_zones(Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
        if z["ZoneId"] not in _NO_LAMBDA_ZONES)
    assert zones, "no available availability zone can hold a Lambda VPC subnet"
    made["subnet"] = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_NET_CIDR.replace("/16", "/24"), AvailabilityZone=zones[0][1],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}])["Subnet"]["SubnetId"]
    sgs = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]
    assert len(sgs) == 1, f"VPC {vpc_id} must have exactly one default security group: {sgs!r}"
    return vpc_id, _NET_CIDR, made["subnet"], sgs[0]["GroupId"]


def _delete_network(ec2, made, budget=240):
    """Delete the subnet and then the VPC, tolerating a resource that is already gone.

    By the time this runs, run() has drained the querier's ENI, so a DependencyViolation here is a
    short tail; one that outlasts the budget is raised, so a stranded VPC fails the cleanup loudly.
    """
    deadline = time.time() + budget
    while True:
        try:
            if made.get("subnet"):
                try:
                    ec2.delete_subnet(SubnetId=made["subnet"])
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") != "InvalidSubnetID.NotFound":
                        raise
                made.pop("subnet")
            try:
                ec2.delete_vpc(VpcId=made["vpc"])
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidVpcID.NotFound":
                    raise
            return
        except ClientError as exc:
            if (exc.response.get("Error", {}).get("Code") != "DependencyViolation"
                    or time.time() >= deadline):
                raise
            time.sleep(10)


def _drain_querier(ctx, made, budget=1200):
    """Delete the querier and wait until Lambda releases its ENI from the subnet.

    DeleteFunction returns before Lambda removes the function's VPC ENI, and until then the subnet
    cannot be deleted. An ENI that reaches `available` is deleted here; the rest is waited for.
    A drain that outlasts the budget is printed and the network cleanup then fails.
    """
    if not made.get("subnet"):
        return
    ec2 = ctx.client("ec2")
    if made.get("fn"):
        try:
            ctx.client("lambda").delete_function(FunctionName=made["fn"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
    deadline = time.time() + budget
    while True:
        enis = ec2.describe_network_interfaces(Filters=[
            {"Name": "subnet-id", "Values": [made["subnet"]]}])["NetworkInterfaces"]
        if not enis:
            return
        for eni in enis:
            if eni.get("Status") == "available":
                try:
                    ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                            "InvalidNetworkInterfaceID.NotFound", "InvalidNetworkInterfaceID.InUse"):
                        raise
        if time.time() >= deadline:
            print(f"subnet {made['subnet']} still holds "
                  f"{[e['NetworkInterfaceId'] for e in enis]!r} after {budget}s")
            return
        time.sleep(2)


def _delete_fn_quietly(lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _in_vpc_resolver(ctx, scenario, made):
    """Stand up the in-VPC DNS querier in a VPC this check creates; return (vpc_id, cidr, dig)."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    cwl = ctx.client("logs")
    kv = [{"Key": "sim2real", "Value": scenario}]

    vpc_id, cidr, subnet, sg_id = _own_network(ctx, made, scenario)

    role = ctx.unique_name("sim2real-r53r-dnsfn-")
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=_TRUST,
                               Description="sim2real in-VPC DNS querier",
                               Tags=kv)["Role"]["Arn"]
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    iam.attach_role_policy(RoleName=role, PolicyArn=_VPC_EXEC)
    ctx.on_cleanup(lambda n=role: iam.detach_role_policy(RoleName=n, PolicyArn=_VPC_EXEC))

    fn = ctx.unique_name("sim2real-r53r-dig-")
    # create_role returns before Lambda can assume the role and no API reports when it becomes
    # usable, so the bounded retry sits on the first call that needs the permission.
    deadline = time.time() + 180
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip_bytes(_DNS_LAMBDA)}, Timeout=30, MemorySize=256,
                VpcConfig={"SubnetIds": [subnet], "SecurityGroupIds": [sg_id]},
                Tags={"sim2real": scenario})
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            assert time.time() < deadline, f"Lambda never accepted role {role_arn!r}: {exc}"
            time.sleep(5)
    made["fn"] = fn
    ctx.on_cleanup(lambda n=fn: _delete_fn_quietly(lam, n))

    def _drop_fn_log_group(g=f"/aws/lambda/{fn}"):
        # Lambda -- not this check -- creates /aws/lambda/<fn> on the first invoke, so it is a child
        # nothing registers by default. Registered AFTER delete_function
        # so LIFO runs it FIRST, while the group is certainly already there: the queries below all
        # happen minutes before cleanup, so this does not race the group into existence and lose.
        try:
            cwl.delete_log_group(logGroupName=g)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_drop_fn_log_group)

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

    return vpc_id, cidr, dig


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
        time.sleep(3)


def _await_assoc(r53, assoc_id, budget=300):
    """Statuses seen while a firewall rule group association converges on COMPLETE.

    Bounded and asserted rather than slept through: an emulator that parks the association in
    UPDATING for ever is exactly the defect this poll is here to catch, and real AWS passes through
    it in about a minute.
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


def _associate(ctx, r53, grp_id, vpc_id, kv):
    """Associate the rule group with the VPC at a FREE association priority.

    Association priority is unique per VPC, so a hardcoded literal can collide with an association
    that already holds that slot -- a failure that has nothing to do with the rule
    being graded. The retry picks another number instead of reporting a fidelity problem.
    """
    last = None
    for _ in range(8):
        try:
            return r53.associate_firewall_rule_group(
                CreatorRequestId=ctx.unique_name("sim2real-cr-"), FirewallRuleGroupId=grp_id,
                VpcId=vpc_id, Priority=random.randrange(1000, 9000),
                Name=ctx.unique_name("sim2real-r53r-fga-"),
                Tags=kv)["FirewallRuleGroupAssociation"]["Id"]
        except ClientError as exc:
            last = exc
            time.sleep(3)
    raise AssertionError(
        f"could not associate the rule group with {vpc_id} at any priority: {last}")


def _dropper(r53, assoc_id):
    """A cleanup that disassociates the rule group AND waits for it to be gone.

    The wait is load-bearing: disassociation is asynchronous, and delete_firewall_rule_group -- the
    cleanup registered before this one, so it runs after -- is refused while the association exists.
    """
    def _drop():
        try:
            r53.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                r53.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(5)
        print(f"firewall rule group association {assoc_id} never disappeared")
    return _drop



def _claim(ctx, made) -> None:
    """The claim; run() wraps it so the querier ENI drains inside the check budget."""
    r53 = ctx.client("route53resolver")
    kv = [{"Key": "sim2real", "Value": _SCENARIO}]
    blocked, control = "example.com", "example.org"

    vpc_id, _cidr, dig = _in_vpc_resolver(ctx, _SCENARIO, made)

    before = dig((blocked, "A"), (control, "A"))
    assert before[0]["answers"], (
        f"{blocked} did not resolve from inside the VPC before any rule existed, so blocking it "
        f"below would prove nothing: {before[0]!r}")
    assert before[1]["answers"], (
        f"the control domain {control} did not resolve before any rule existed: {before[1]!r}")

    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-fdl-"), Tags=kv)["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))
    r53.update_firewall_domains(FirewallDomainListId=dl_id, Operation="ADD", Domains=[blocked])

    grp_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-frg-"), Tags=kv)["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=grp_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"), FirewallRuleGroupId=grp_id,
        FirewallDomainListId=dl_id, Priority=100, Action="BLOCK", BlockResponse="NXDOMAIN",
        Name=ctx.unique_name("sim2real-r53r-fr-"))
    ctx.on_cleanup(lambda g=grp_id, d=dl_id: r53.delete_firewall_rule(
        FirewallRuleGroupId=g, FirewallDomainListId=d))

    assoc_id = _associate(ctx, r53, grp_id, vpc_id, kv)
    drop = _dropper(r53, assoc_id)
    ctx.on_cleanup(drop)
    seen = _await_assoc(r53, assoc_id)
    assert seen[-1] == "COMPLETE", f"the association never completed: statuses were {seen!r}"

    after = _poll_dns(
        dig, ((blocked, "A"), (control, "A")),
        lambda got: got[0]["rcode"] == "NXDOMAIN",
        180, f"the BLOCK rule never stopped the VPC resolver answering {blocked}")
    assert not after[0]["answers"], (
        f"the BLOCK rule answered NXDOMAIN but still carried answer records: {after[0]!r}")
    assert after[1]["answers"], (
        f"the control domain {control} stopped resolving too, so the block is not scoped to the "
        f"domain list: {after[1]!r}")

    drop()
    restored = _poll_dns(
        dig, ((blocked, "A"),), lambda got: bool(got[0]["answers"]),
        240, f"removing the association never restored resolution of {blocked}")
    assert restored[0]["rcode"] == "NOERROR", (
        f"resolution came back with the wrong rcode: {restored[0]!r}")


@tags("axis:rejection", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A BLOCK rule stops the VPC resolver answering the listed domain, and only that domain, and
    removing the association restores it: read from real queries inside the VPC, since the control
    plane only stores the rule.
    """
    made = {}
    try:
        _claim(ctx, made)
    finally:
        _drain_querier(ctx, made)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
