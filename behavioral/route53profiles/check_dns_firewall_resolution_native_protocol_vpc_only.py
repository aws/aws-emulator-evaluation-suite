"""dns-firewall-resolution-native-protocol-vpc-only."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dns-firewall-resolution-native-protocol-vpc-only"
GROUP = "native-protocol"
SERVICES = ["route53profiles"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A DNS Firewall BLOCK rule wired through a Route 53 Profile settles COMPLETE at every hop with
    the right linkage, and a native DNS query from inside the associated VPC gets NXDOMAIN for
    the blocked domain once the association is COMPLETE while a control domain keeps resolving."""
    r53p = ctx.client("route53profiles")
    resolver = ctx.client("route53resolver")

    vpc_id, subnet_id = _create_vpc(ctx)
    profile_id = _create_profile(ctx)

    # Real, publicly-resolvable domains: DNS Firewall matches by domain-list membership, not by
    # whether the name is otherwise fake, but a twin control that both resolve BEFORE any rule
    # exists is what makes a later NXDOMAIN on only one of them mean something.
    blocked_domain = "example.com."
    control_domain = "example.net."
    dig = _in_vpc_dns_querier(ctx, vpc_id, subnet_id)

    before = dig((blocked_domain, "A"), (control_domain, "A"))
    assert before[0]["answers"], (
        f"{blocked_domain!r} did not resolve from inside the fresh VPC before any firewall rule "
        f"existed, so blocking it below would prove nothing: {before[0]!r}"
    )
    assert before[1]["answers"], (
        f"the control domain {control_domain!r} did not resolve from inside the fresh VPC before "
        f"any firewall rule existed: {before[1]!r}"
    )

    domain_list_id = _create_firewall_domain_list(ctx, blocked_domain)
    rule_group_id, rule_group_arn = _create_firewall_rule_group(ctx)
    resolver.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-rule-"),
        FirewallRuleGroupId=rule_group_id,
        FirewallDomainListId=domain_list_id,
        Priority=1,
        Action="BLOCK",
        BlockResponse="NXDOMAIN",
        Name=ctx.unique_name("sim2real-behav-block-"),
    )
    ctx.on_cleanup(
        lambda: resolver.delete_firewall_rule(
            FirewallRuleGroupId=rule_group_id, FirewallDomainListId=domain_list_id
        )
    )

    # 1) wire the rule group into the Profile as a resource association
    res_assoc = r53p.associate_resource_to_profile(
        ProfileId=profile_id,
        ResourceArn=rule_group_arn,
        Name=ctx.unique_name("sim2real-behav-resassoc-"),
        ResourceProperties='{"priority": 110}',
    )["ProfileResourceAssociation"]
    res_assoc_id = res_assoc["Id"]
    ctx.on_cleanup(
        lambda: r53p.disassociate_resource_from_profile(ProfileId=profile_id, ResourceArn=rule_group_arn)
    )

    res_status = _poll_until(
        probe=lambda: r53p.get_profile_resource_association(ProfileResourceAssociationId=res_assoc_id)[
            "ProfileResourceAssociation"
        ]["Status"],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert res_status == "COMPLETE", f"resource association settled into {res_status!r}, not COMPLETE"
    res_assoc_fetched = r53p.get_profile_resource_association(ProfileResourceAssociationId=res_assoc_id)[
        "ProfileResourceAssociation"
    ]
    assert res_assoc_fetched["ResourceArn"] == rule_group_arn
    assert res_assoc_fetched["ResourceType"] == "FIREWALL_RULE_GROUP"

    # 2) wire the Profile itself onto the VPC
    vpc_assoc = r53p.associate_profile(
        ProfileId=profile_id, ResourceId=vpc_id, Name=ctx.unique_name("sim2real-behav-assoc-")
    )["ProfileAssociation"]
    vpc_assoc_id = vpc_assoc["Id"]
    ctx.on_cleanup(lambda: r53p.disassociate_profile(ProfileId=profile_id, ResourceId=vpc_id))

    vpc_status = _poll_until(
        probe=lambda: r53p.get_profile_association(ProfileAssociationId=vpc_assoc_id)[
            "ProfileAssociation"
        ]["Status"],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=420,
        interval_s=5,
    )
    assert vpc_status == "COMPLETE", f"VPC association settled into {vpc_status!r}, not COMPLETE"
    vpc_assoc_fetched = r53p.get_profile_association(ProfileAssociationId=vpc_assoc_id)[
        "ProfileAssociation"
    ]
    assert vpc_assoc_fetched["ResourceId"] == vpc_id
    assert vpc_assoc_fetched["ProfileId"] == profile_id

    # The whole control-plane chain (domain list -> rule -> rule group -> Profile -> VPC) is now
    # verifiably wired and COMPLETE. That is a control-plane fact; whether the VPC's own Resolver
    # has actually started applying it is only observable in a real DNS answer issued from inside
    # the VPC, and no API reports that -- so the answer is the terminal read, polled rather than
    # slept for, because propagation into the data plane lags COMPLETE by design.
    after = _poll_dns(
        dig, ((blocked_domain, "A"), (control_domain, "A")),
        lambda got: got[0]["rcode"] == "NXDOMAIN",
        180, f"the Profile's BLOCK rule never stopped the VPC's Resolver answering {blocked_domain!r}",
    )
    assert not after[0]["answers"], (
        f"{blocked_domain!r} rcode was NXDOMAIN but the answer still carried records: {after[0]!r}"
    )
    assert after[1]["answers"], (
        f"the control domain {control_domain!r} stopped resolving too, so the block reached the "
        f"whole Resolver rather than just the domain the Profile's rule names: {after[1]!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _create_vpc(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.83.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    # A subnet is what gives the in-VPC DNS querier's Lambda ENI somewhere to attach; the Profile
    # associates to the VPC as a whole, so which subnet carries the ENI is otherwise unconstrained.
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.83.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


# A DNS resolver in pure stdlib, deployed as a Lambda function with a VPC ENI so its queries
# originate INSIDE the VPC under test. Route 53's data plane answers in-VPC sources only, so this
# is the only way to observe it at all -- nothing the harness itself can call ever sees a DNS
# answer. It parses the wire format structurally and returns the rcode plus every answer record's
# name/ttl/type/rdata, instead of scraping a text tool's output.
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
    return {"results": [_one(q["name"], q.get("type", "A"), server, timeout)
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


def _in_vpc_dns_querier(ctx, vpc_id: str, subnet_id: str):
    """Stand up a Lambda function with an ENI inside `vpc_id`/`subnet_id` and return a `dig`
    callable that issues real DNS queries through it, so a query actually originates inside the
    VPC whose Resolver the Profile's BLOCK rule is supposed to affect."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    sgs = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]},
    ])["SecurityGroups"]
    assert sgs, f"VPC {vpc_id} has no default security group"

    role = ctx.unique_name("sim2real-behav-dnsfn-")
    role_arn = iam.create_role(
        RoleName=role, AssumeRolePolicyDocument=_TRUST,
        Description="sim2real in-VPC DNS querier",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_VPC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role, PolicyArn=_VPC_EXEC))

    fn = ctx.unique_name("sim2real-behav-dig-")
    # create_role returns before Lambda can assume the role and no API reports when it becomes
    # usable, so the bounded retry sits on the first call that needs the permission.
    deadline = time.monotonic() + 180
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip_bytes(_DNS_LAMBDA)}, Timeout=30, MemorySize=256,
                VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sgs[0]["GroupId"]]},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            assert time.monotonic() < deadline, f"Lambda never accepted role {role_arn!r}: {err}"
            time.sleep(5)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))

    # The function cannot be invoked until its VPC ENI exists; State is the observable condition.
    deadline = time.monotonic() + 600
    while True:
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Active":
            break
        assert cfg["State"] == "Pending" and time.monotonic() < deadline, (
            f"the in-VPC querier never became Active: State={cfg['State']!r} "
            f"reason={cfg.get('StateReason')!r}"
        )
        time.sleep(5)

    def dig(*queries):
        resp = lam.invoke(FunctionName=fn, Payload=json.dumps(
            {"queries": [{"name": n, "type": t} for n, t in queries]}).encode())
        body = json.loads(resp["Payload"].read())
        assert "FunctionError" not in resp, f"the in-VPC querier failed: {body!r}"
        return body["results"]

    return dig


def _poll_dns(dig, queries, predicate, budget, what):
    """Poll the resolver's OWN ANSWER until predicate holds.

    A configuration change reaching COMPLETE is a control-plane fact; whether the resolver has
    started applying it is only observable in the answer, and no API reports that. So the answer
    is the condition -- never a fixed sleep sized to make this pass.
    """
    deadline = time.monotonic() + budget
    while True:
        got = dig(*queries)
        if predicate(got):
            return got
        assert time.monotonic() < deadline, f"{what}; the last answer was {got!r}"
        time.sleep(3)


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    deadline = time.monotonic() + 400
    while True:
        try:
            profile_id = r53p.create_profile(
                Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-")
            )["Profile"]["Id"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() > deadline:
                raise
            time.sleep(15)
    ctx.on_cleanup(lambda: _delete_profile_blocking(r53p, profile_id))
    return profile_id


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    try:
        r53p.delete_profile(ProfileId=profile_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            r53p.get_profile(ProfileId=profile_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)


def _create_firewall_domain_list(ctx, domain: str) -> str:
    resolver = ctx.client("route53resolver")
    name = ctx.unique_name("sim2real-behav-domains-")
    domain_list_id = resolver.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-crid-"), Name=name
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: resolver.delete_firewall_domain_list(FirewallDomainListId=domain_list_id))
    resolver.update_firewall_domains(
        FirewallDomainListId=domain_list_id, Operation="ADD", Domains=[domain]
    )
    return domain_list_id


def _create_firewall_rule_group(ctx) -> tuple[str, str]:
    resolver = ctx.client("route53resolver")
    name = ctx.unique_name("sim2real-behav-frg-")
    rule_group = resolver.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-crid-"), Name=name
    )["FirewallRuleGroup"]
    rule_group_id = rule_group["Id"]
    ctx.on_cleanup(lambda: resolver.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id))
    return rule_group_id, rule_group["Arn"]


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
