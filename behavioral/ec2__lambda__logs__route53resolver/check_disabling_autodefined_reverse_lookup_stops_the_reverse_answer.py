"""disabling-autodefined-reverse-lookup-stops-the-reverse-answer."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "disabling-autodefined-reverse-lookup-stops-the-reverse-answer"
GROUP = 'resolver-config-data-plane'
SERVICES = ['ec2', 'lambda', 'logs', 'route53resolver']

_SCENARIO = 'r53r-autodefined-reverse'

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
    try:
        ec2.get_waiter("vpc_available").wait(
            VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 600) // 2))})
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"VPC {vpc_id} available: the run budget ended first; not graded") from None
        raise
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _claim(ctx, made) -> None:
    """The claim; run() wraps it so the querier ENI drains inside the check budget."""
    r53 = ctx.client("route53resolver")
    vpc_id, cidr, dig = _in_vpc_resolver(ctx, _SCENARIO, made)

    octets = cidr.split("/")[0].split(".")
    ip = f"{octets[0]}.{octets[1]}.{octets[2]}.5"
    reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    forward = f"ip-{ip.replace('.', '-')}.{ctx.region}.compute.internal"

    # The VPC resolver's autodefined answers may lag a brand-new VPC; poll, then grade the last.
    deadline = time.time() + _budget_s(ctx, 120)
    while True:
        before = dig((reverse, "PTR"), (forward, "A"))
        if (before[0]["answers"] and before[1]["answers"]) or time.time() >= deadline:
            break
        time.sleep(1)
    if not (before[0]["answers"] and before[1]["answers"]) and _budget_spent(ctx):
        raise TimeoutError(f"the autodefined answers for {reverse} and {forward}: the run budget "
                           f"ended first; not graded")
    assert before[0]["answers"], (
        f"the autodefined reverse zone did not answer {reverse} before the change, so disabling "
        f"it below would prove nothing: {before[0]!r}")
    assert before[0]["answers"][0]["rdata"].rstrip(".") == forward, (
        f"the PTR answer is not the VPC's internal name for {ip}: {before[0]!r}")
    assert before[1]["answers"] and before[1]["answers"][0]["rdata"] == ip, (
        f"the forward name {forward} did not resolve to {ip} before the change: {before[1]!r}")

    r53.update_resolver_config(ResourceId=vpc_id, AutodefinedReverseFlag="DISABLE")

    def _restore(v=vpc_id):
        r53.update_resolver_config(ResourceId=v, AutodefinedReverseFlag="ENABLE")
        deadline = time.time() + 420
        while time.time() < deadline:
            if r53.get_resolver_config(ResourceId=v)["ResolverConfig"][
                    "AutodefinedReverse"] == "ENABLED":
                return
            time.sleep(2)
        raise RuntimeError(f"{v} left with AutodefinedReverse not restored to ENABLED")

    # Registered immediately, before any assertion: this is per-VPC state on a shared object, so a
    # failing assert must not be able to leave the VPC's reverse resolution switched off.
    ctx.on_cleanup(_restore)

    seen = []
    deadline = time.time() + _budget_s(ctx, 420)
    while True:
        seen.append(r53.get_resolver_config(ResourceId=vpc_id)["ResolverConfig"][
            "AutodefinedReverse"])
        if seen[-1] == "DISABLED":
            break
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"the resolver config of {vpc_id} DISABLED: the run budget ended first; "
                               f"not graded")
        assert time.time() < deadline, (
            f"the resolver config never reported DISABLED -- statuses were {seen[-8:]!r}")
        time.sleep(1)

    after = _poll_dns(
        ctx, dig, ((reverse, "PTR"), (forward, "A")),
        lambda got: not got[0]["answers"],
        240, f"disabling AutodefinedReverse never stopped the PTR answer for {reverse}")
    assert after[0]["rcode"] == "NXDOMAIN", (
        f"the reverse lookup stopped answering but with the wrong rcode: {after[0]!r}")
    assert after[1]["answers"] and after[1]["answers"][0]["rdata"] == ip, (
        f"the forward lookup broke too, so the change is not scoped to reverse resolution: "
        f"{after[1]!r}")


@tags("axis:rejection", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c3")
def run(ctx) -> None:
    """Disabling AutodefinedReverse stops in-VPC PTR answers for the VPC CIDR, and only those.

    The forward name still resolves afterwards, so the change is scoped to reverse resolution.
    """
    made = {}
    try:
        _claim(ctx, made)
    finally:
        _drain_querier(ctx, made)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
