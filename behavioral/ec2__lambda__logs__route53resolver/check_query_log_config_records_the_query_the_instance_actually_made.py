"""query-log-config-records-the-query-the-instance-actually-made."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "query-log-config-records-the-query-the-instance-actually-made"
GROUP = 'query-logging'
SERVICES = ['ec2', 'lambda', 'logs', 'route53resolver']

_SCENARIO = 'r53r-query-log'

# A stdlib DNS client run as a VPC-attached Lambda: Route 53 Resolver answers in-VPC sources only.
# It parses the DNS wire format and returns the rcode plus every answer's name/ttl/type/rdata.
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _own_network(ctx, made, scenario):
    """Create the querier's VPC (DNS support and hostnames on) with one subnet.

    Its cleanup runs last; the Lambda ENI is drained inside run() first because its release can
    outlast the cleanup budget.
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
    """Delete the subnet and then the VPC, tolerating one already gone.

    A DependencyViolation that outlasts the budget is raised so a stranded VPC fails the cleanup.
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
            time.sleep(2)


def _drain_querier(ctx, made, budget=1200):
    """Delete the querier and wait until Lambda releases its ENI from the subnet.

    DeleteFunction returns before the VPC ENI is removed, and the subnet cannot be deleted until
    then. An ENI that reaches `available` is deleted here; the rest is waited for.
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
    budget = _budget_s(ctx, budget)
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
                except ClientError:
                    pass
        if time.time() >= deadline:
            # Still pinned: the registered _delete_network retries the subnet and raises if it stays.
            made["pinned_enis"] = [e["NetworkInterfaceId"] for e in enis]
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
    deadline = time.time() + _budget_s(ctx, 180)
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
            if time.time() >= deadline and _budget_spent(ctx):
                raise TimeoutError(f"Lambda accepting role {role_arn!r}: the run budget ended first; "
                                   f"not graded") from exc
            assert time.time() < deadline, f"Lambda never accepted role {role_arn!r}: {exc}"
            time.sleep(2)
    made["fn"] = fn
    ctx.on_cleanup(lambda n=fn: _delete_fn_quietly(lam, n))

    def _drop_fn_log_group(g=f"/aws/lambda/{fn}"):
        # Lambda creates /aws/lambda/<fn> on first invoke. Registered after delete_function so LIFO
        # runs it first, by which time the invokes below have long since created the group.
        try:
            cwl.delete_log_group(logGroupName=g)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_drop_fn_log_group)

    # The function cannot be invoked until its VPC ENI exists; State is the observable condition.
    deadline = time.time() + _budget_s(ctx, 600)
    while True:
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Active":
            break
        if cfg["State"] == "Pending" and time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"the in-VPC querier {fn} Active: the run budget ended first; not graded")
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

    return vpc_id, cidr, dig


def _poll_dns(ctx, dig, queries, predicate, budget, what):
    """Poll the resolver's own answer until predicate holds.

    A config reaching COMPLETE does not mean the resolver applies it yet; only the answer shows that.
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


def _private_zone(ctx, scenario, vpc_id, labels):
    """A private hosted zone associated with the VPC, one A record per label.

    Returns (zone_name, {label: ip}). The check owning its own namespace is what makes the
    resolver's answer deterministic instead of a bet on a third party's records.
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
    try:
        r53z.get_waiter("resource_record_sets_changed").wait(
            Id=change, WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 300) // 2))})
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"record change {change} INSYNC: the run budget ended first; not graded") \
                from None
        raise
    return zone, ips


def _query_log(ctx, scenario, vpc_id):
    """Associate a resolver query log config with the VPC; return (log_group, find).

    find(predicate, budget) pages filter_log_events and returns the first parsed record the
    predicate accepts, so the assertion is made against a structurally parsed record rather than a
    substring of a log line.
    """
    logs = ctx.client("logs")
    r53 = ctx.client("route53resolver")
    lg = ctx.unique_name("/sim2real/r53r/")
    logs.create_log_group(logGroupName=lg, tags={"sim2real": scenario})
    ctx.on_cleanup(lambda g=lg: logs.delete_log_group(logGroupName=g))
    arn = logs.describe_log_groups(logGroupNamePrefix=lg)["logGroups"][0]["arn"]
    cfg_id = r53.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-r53r-qlc-"), DestinationArn=arn,
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Tags=[{"Key": "sim2real", "Value": scenario}])["ResolverQueryLogConfig"]["Id"]
    ctx.on_cleanup(lambda q=cfg_id: r53.delete_resolver_query_log_config(
        ResolverQueryLogConfigId=q))
    assoc_id = r53.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=cfg_id,
        ResourceId=vpc_id)["ResolverQueryLogConfigAssociation"]["Id"]

    def _drop(q=cfg_id, v=vpc_id):
        try:
            r53.disassociate_resolver_query_log_config(ResolverQueryLogConfigId=q, ResourceId=v)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        deadline = time.time() + 300
        while time.time() < deadline:
            left = []
            for page in r53.get_paginator(
                    "list_resolver_query_log_config_associations").paginate(
                    Filters=[{"Name": "ResolverQueryLogConfigId", "Values": [q]}]):
                left += page["ResolverQueryLogConfigAssociations"]
            if not left:
                return
            time.sleep(2)
        raise RuntimeError(f"query log config association for {q} never disappeared")

    ctx.on_cleanup(_drop)
    deadline = time.time() + _budget_s(ctx, 300)
    while True:
        st = r53.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )["ResolverQueryLogConfigAssociation"]["Status"]
        if st == "ACTIVE":
            break
        if st == "CREATING" and time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"query log config association {assoc_id} ACTIVE: the run budget ended "
                               f"first; not graded")
        assert st == "CREATING" and time.time() < deadline, (
            f"the query log config association never became ACTIVE: {st!r}")
        time.sleep(1)

    def find(predicate, budget=420, retry=None):
        deadline = time.time() + _budget_s(ctx, budget)
        scanned = 0
        while True:
            if retry is not None:
                retry()
            for page in logs.get_paginator("filter_log_events").paginate(
                    logGroupName=lg, startTime=int((time.time() - 1800) * 1000)):
                for ev in page.get("events", []):
                    scanned += 1
                    try:
                        rec = json.loads(ev["message"])
                    except ValueError:
                        continue
                    if predicate(rec):
                        return rec
            if time.time() >= deadline and _budget_spent(ctx):
                raise TimeoutError(f"a matching resolver query log record in {lg!r}: the run budget "
                                   f"ended first; not graded")
            assert time.time() < deadline, (
                f"no resolver query log record in {lg!r} matched after scanning {scanned} records")
            time.sleep(2)

    return lg, find


def _claim(ctx, made) -> None:
    """The claim; run() wraps it so the querier ENI drains inside the check budget."""
    vpc_id, cidr, dig = _in_vpc_resolver(ctx, _SCENARIO, made)
    # A wildcard record lets each subject name be queried exactly once: the zone becomes visible
    # seconds after INSYNC, and polling on the subject name would log NXDOMAINs for it first.
    zone, ips = _private_zone(ctx, _SCENARIO, vpc_id, ["*"])
    expected_ip = ips["*"]
    _lg, find = _query_log(ctx, _SCENARIO, vpc_id)

    _poll_dns(
        ctx, dig, ((f"warm-{ctx.unique_name('')}.{zone}", "A"),),
        lambda got: bool(got[0]["answers"]),
        300, f"the wildcard record in {zone} never became visible to the VPC resolver")
    # The wildcard can answer one label while another still returns nothing, so each attempt uses a
    # fresh name and the log search keys on the one that answered (queried exactly once).
    fqdn, served = None, None
    deadline = time.time() + _budget_s(ctx, 300)
    while True:
        fqdn = f"subject-{ctx.unique_name('')}.{zone}"
        served = dig((fqdn, "A"))
        if served[0]["answers"]:
            break
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"a fresh name under the private zone {zone} resolving: the run budget "
                               f"ended first; not graded")
        assert time.time() < deadline, (
            f"no fresh name under the private zone {zone} resolved from inside the VPC, so there "
            f"is no successful query for the log to have recorded: {served[0]!r}")
        time.sleep(1)
    assert served[0]["answers"][0]["rdata"] == expected_ip, (
        f"the resolver served the wrong answer for {fqdn}: {served[0]!r}")

    rec = find(lambda r: r.get("query_name", "").rstrip(".").lower() == fqdn.lower())
    assert rec["query_type"] == "A", f"the logged query type is wrong: {rec!r}"
    assert rec["rcode"] == "NOERROR", f"the logged query did not succeed: {rec!r}"
    assert rec["vpc_id"] == vpc_id, f"the record names a different VPC: {rec!r}"
    net = cidr.split("/")[0].rsplit(".", 2)[0]
    assert rec["srcaddr"].startswith(net + "."), (
        f"the record's source {rec['srcaddr']!r} is not inside the VPC CIDR {cidr!r}: {rec!r}")
    assert "instance" in rec.get("srcids", {}), (
        f"the record does not attribute the query to a source inside the VPC: {rec!r}")
    logged = {a.get("Rdata", "").rstrip(".") for a in rec.get("answers", [])}
    assert logged == {expected_ip}, (
        f"the record logged answers {logged!r}, not the address the resolver served "
        f"({expected_ip!r}): {rec!r}")


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """A resolver query log records the exact in-VPC query: name, type, rcode, source and answer.

    No API status shows a query was seen; only the log record proves the resolver processed it.
    """
    made = {}
    try:
        _claim(ctx, made)
    finally:
        _drain_querier(ctx, made)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
