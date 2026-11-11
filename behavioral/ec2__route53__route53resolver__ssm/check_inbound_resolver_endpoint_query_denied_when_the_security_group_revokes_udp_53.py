"""inbound-resolver-endpoint-query-denied-when-the-security-group-revokes-udp-53."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "inbound-resolver-endpoint-query-denied-when-the-security-group-revokes-udp-53"
GROUP = 'resolver-endpoint-data-plane'
SERVICES = ['ec2', 'route53', 'route53resolver', 'ssm']

_SCENARIO = 'r53r-endpoint-data-plane'

_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDRS = ("10.91.1.0/24", "10.91.2.0/24")

#: The link-local address every VPC answers DNS on, identical in every VPC and region.
_VPC_RESOLVER = "169.254.169.253"

#: TEST-NET-1 (RFC 5737). Deliberately outside _VPC_CIDR, so an answer carrying it cannot have come
#: from anything but the record this check wrote.
_ZONE_RECORD_IP = "192.0.2.10"

_INSTANCE_RUNNING_TIMEOUT_S = 300.0
_AGENT_ONLINE_TIMEOUT_S = 420.0
_COMMAND_TIMEOUT_S = 240.0
_ENDPOINT_READY_TIMEOUT_S = 600.0
_DNS_CONVERGE_TIMEOUT_S = 300.0
_TEARDOWN_TIMEOUT_S = 420.0

_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GONE = ("InvalidInstanceID.NotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
         "InvalidGroup.NotFound", "InvalidInternetGatewayID.NotFound", "NoSuchEntity",
         "ResourceNotFoundException", "NoSuchHostedZone", "InvalidPermission.NotFound")



#: A wire-format DNS client run on the instance: Resolver answers in-VPC sources only. It takes one
#: JSON argument and prints one JSON line.
_DIG_PY = r"""
import json
import random
import socket
import struct
import sys

_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
_TYPENUM = {v: k for k, v in _TYPES.items()}


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


def _exchange(pkt, server, timeout, proto):
    if proto == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((server, 53))
            s.sendall(struct.pack("!H", len(pkt)) + pkt)
            head = s.recv(2)
            if len(head) < 2:
                return None, "NOANSWER"
            want = struct.unpack("!H", head)[0]
            data = b""
            while len(data) < want:
                chunk = s.recv(want - len(data))
                if not chunk:
                    break
                data += chunk
            return data, None
        except socket.timeout:
            return None, "TIMEOUT"
        except OSError as exc:
            return None, "NETERR:%s" % (exc.errno,)
        finally:
            s.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(65535)
        return data, None
    except socket.timeout:
        return None, "TIMEOUT"
    except OSError as exc:
        return None, "NETERR:%s" % (exc.errno,)
    finally:
        s.close()


def _one(qname, qtype, server, timeout, proto):
    tid = random.randrange(1, 65535)
    pkt = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    pkt += _enc(qname) + struct.pack("!HH", _TYPENUM[qtype], 1)
    data, failure = _exchange(pkt, server, timeout, proto)
    if failure is not None:
        return {"query": qname, "qtype": qtype, "server": server, "proto": proto,
                "rcode": failure, "answers": []}
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
    return {"query": qname, "qtype": qtype, "server": server, "proto": proto,
            "id_match": rid == tid,
            "rcode": _RCODES.get(flags & 0xF, str(flags & 0xF)), "answers": answers}


spec = json.loads(sys.argv[1])
print(json.dumps({"results": [_one(q["name"], q["type"], q["server"], float(spec["timeout"]),
                                   q.get("proto", "udp"))
                              for q in spec["queries"]]}))
"""


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Bounded retry that raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _call_with_retry(fn, codes=_THROTTLE, retries=40, delay=3.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": _SCENARIO}]


def _usable_zones(ec2, region, want):
    """*want* AZs that are both available and offer the instance type. No hardcoded zone."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert len(usable) >= want, (
        f"a resolver endpoint needs {want} availability zones that also offer {_INSTANCE_TYPE}; "
        f"{region} offers {sorted(offered)!r} and reports {sorted(available)!r} available")
    return usable[:want]


def _dns_permission(sg_id, proto):
    """The one ingress rule that carries DNS between the instance and the resolver endpoint."""
    return {"IpProtocol": proto, "FromPort": 53, "ToPort": 53,
            "UserIdGroupPairs": [{"GroupId": sg_id}]}


def _build_network(ec2, region, name, st):
    """A VPC with two public subnets in two AZs and one security group, reachable by SSM.

    The group permits udp and tcp/53 from itself only, so instance and endpoint exchange DNS.
    """
    st["vpc"] = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags(name)}])["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[st["vpc"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    # Both attributes are required before a private hosted zone is answered inside the VPC.
    ec2.modify_vpc_attribute(VpcId=st["vpc"], EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=st["vpc"], EnableDnsHostnames={"Value": True})

    st["igw"] = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags(name)}],
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=st["igw"], VpcId=st["vpc"])

    main_rt = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [st["vpc"]]}])["RouteTables"]
    assert len(main_rt) == 1, (
        f"a freshly created VPC must have exactly one (main) route table; got "
        f"{[r['RouteTableId'] for r in main_rt]!r}")
    ec2.create_route(RouteTableId=main_rt[0]["RouteTableId"],
                     DestinationCidrBlock="0.0.0.0/0", GatewayId=st["igw"])

    zones = _usable_zones(ec2, region, 2)
    st["subnets"] = []
    for cidr, zone in zip(_SUBNET_CIDRS, zones):
        subnet = ec2.create_subnet(
            VpcId=st["vpc"], CidrBlock=cidr, AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(name)}],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
        st["subnets"].append(subnet)

    st["sg"] = ec2.create_security_group(
        GroupName=name, Description="sim2real route53resolver endpoint data plane",
        VpcId=st["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags(name)}])["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=st["sg"],
        IpPermissions=[_dns_permission(st["sg"], proto) for proto in ("udp", "tcp")])
    return st["vpc"]


def _instance_role(iam, name):
    """A role trusting EC2 and able to register with SSM. Returns the instance profile name."""
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}),
        Description="sim2real route53resolver in-VPC DNS client",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


def _launch_client(ec2, iam, ssm, name, st):
    """Launch the in-VPC DNS client and return (instance_id, private_ip)."""
    st["role"] = _instance_role(iam, name)
    st["profile"] = name
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=st["subnets"][0], SecurityGroupIds=[st["sg"]],
            IamInstanceProfile={"Name": st["profile"]},
            TagSpecifications=[{"ResourceType": rt, "Tags": _tags(name)}
                               for rt in ("instance", "volume")]),
        # A brand-new instance profile is not immediately resolvable by RunInstances.
        codes=_THROTTLE + ("InvalidParameterValue",), retries=40, delay=5.0)
    st["instance"] = reservation["Instances"][0]["InstanceId"]
    return st["instance"], reservation["Instances"][0]["PrivateIpAddress"]


def _await_running(ec2, instance_id):
    def _states():
        try:
            return [i["State"]["Name"]
                    for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
                    for i in r["Instances"]]
        except ClientError as exc:
            # DescribeInstances can answer NotFound for a few seconds after RunInstances returned
            # the id. Not-yet-visible is not "not running".
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                return []
            raise

    _poll(_states, lambda s: s == ["running"], timeout_s=_INSTANCE_RUNNING_TIMEOUT_S,
          what=f"instance {instance_id} reaching running")


def _await_agent(ssm, instance_id):
    def _agent():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    agent = _poll(_agent, lambda i: i is not None and i.get("PingStatus") == "Online",
                  timeout_s=_AGENT_ONLINE_TIMEOUT_S, interval_s=10.0,
                  what=f"the SSM agent on {instance_id} coming Online")
    assert agent["ResourceType"] == "EC2Instance", (
        f"the DNS client must be a real EC2 instance inside the VPC; SSM reports "
        f"{agent['ResourceType']!r}")


def _ssm_run(ssm, instance_id, commands, comment):
    """Run a shell script on the instance and return its stdout. Raises unless it succeeded."""
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=int(_COMMAND_TIMEOUT_S),
        Comment=comment[:100]))
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(_invocation, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=_COMMAND_TIMEOUT_S,
                what=f"invocation {command_id} on {instance_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"the in-VPC probe script must run to completion; SSM reports {inv['Status']!r} "
        f"stdout={inv.get('StandardOutputContent')!r} stderr={inv.get('StandardErrorContent')!r}")
    return inv["StandardOutputContent"]


def _dig(ssm, instance_id, queries, timeout=5.0):
    """Resolve *queries* from inside the VPC; each is (name, rrtype, server[, proto]).

    *proto* defaults to udp and may be tcp: a resolver endpoint listens on both, and a security
    group permits each independently, so the two are separately observable.

    Returns the per-query results: the rcode plus every answer record, decoded off the wire.
    """
    spec = json.dumps({"timeout": timeout,
                       "queries": [{"name": q[0], "type": q[1], "server": q[2],
                                    "proto": q[3] if len(q) > 3 else "udp"} for q in queries]})
    assert "'" not in spec, f"the probe argument must be single-quotable, got {spec!r}"
    out = _ssm_run(ssm, instance_id,
                   ["set -uo pipefail",
                    "cat > /tmp/s2rdig.py <<'S2R_DIG_EOF'", _DIG_PY, "S2R_DIG_EOF",
                    f"python3 /tmp/s2rdig.py '{spec}'"],
                   "sim2real route53resolver in-VPC dns probe")
    lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
    assert lines, f"the in-VPC probe printed no JSON line; stdout={out!r}"
    return json.loads(lines[-1])["results"]


def _poll_dns(ssm, instance_id, queries, predicate, budget, what, timeout=5.0):
    """Poll the resolver's own answer until *predicate* holds.

    No API reports when the resolver starts applying a change; only the answer shows it.
    """
    return _poll(lambda: _dig(ssm, instance_id, queries, timeout=timeout), predicate,
                 timeout_s=budget, interval_s=5.0, what=what)


def _rdata(result):
    return [a["rdata"] for a in result["answers"]]


def _private_zone(ctx, r53, vpc_id, st, records):
    """A uniquely named private hosted zone on the VPC, holding *records* as (label, ip).

    Returns the zone name, with its trailing dot.
    """
    zone = f"{ctx.unique_name('s2r')}.internal."
    st["zone_id"] = r53.create_hosted_zone(
        Name=zone, CallerReference=ctx.unique_name("sim2real-cr-"),
        HostedZoneConfig={"Comment": f"sim2real {_SCENARIO}", "PrivateZone": True},
        VPC={"VPCRegion": ctx.region, "VPCId": vpc_id})["HostedZone"]["Id"]
    st["zone_name"] = zone
    st["records"] = [{"Name": f"{label}.{zone}", "Type": "A", "TTL": 60,
                      "ResourceRecords": [{"Value": ip}]} for label, ip in records]
    r53.change_resource_record_sets(
        HostedZoneId=st["zone_id"],
        ChangeBatch={"Comment": f"sim2real {_SCENARIO}",
                     "Changes": [{"Action": "CREATE", "ResourceRecordSet": rr}
                                 for rr in st["records"]]})
    return zone


def _resolver_endpoint(ctx, r53r, name, direction, st):
    """A resolver endpoint with one IP in each created subnet. Returns its id."""
    st["endpoint"] = r53r.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"), Name=name,
        SecurityGroupIds=[st["sg"]], Direction=direction,
        IpAddresses=[{"SubnetId": s} for s in st["subnets"]],
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}])["ResolverEndpoint"]["Id"]
    return st["endpoint"]


def _await_endpoint(r53r, endpoint_id):
    """The statuses seen while the endpoint converges on OPERATIONAL."""
    seen = []

    def _status():
        seen.append(r53r.get_resolver_endpoint(
            ResolverEndpointId=endpoint_id)["ResolverEndpoint"]["Status"])
        return seen[-1]

    _poll(_status, lambda s: s == "OPERATIONAL", timeout_s=_ENDPOINT_READY_TIMEOUT_S,
          interval_s=10.0,
          what=f"resolver endpoint {endpoint_id} reaching OPERATIONAL")
    return seen


def _endpoint_ips(r53r, endpoint_id):
    """Every address the endpoint listens on, following pagination."""
    ips = []
    token = None
    while True:
        kwargs = {"ResolverEndpointId": endpoint_id, "MaxResults": 20}
        if token:
            kwargs["NextToken"] = token
        page = r53r.list_resolver_endpoint_ip_addresses(**kwargs)
        ips.extend(page["IpAddresses"])
        token = page.get("NextToken")
        if not token:
            return ips


def _await_rule_association(r53r, assoc_id):
    seen = []

    def _status():
        seen.append(r53r.get_resolver_rule_association(
            ResolverRuleAssociationId=assoc_id)["ResolverRuleAssociation"]["Status"])
        return seen[-1]

    _poll(_status, lambda s: s == "COMPLETE", timeout_s=_ENDPOINT_READY_TIMEOUT_S, interval_s=5.0,
          what=f"resolver rule association {assoc_id} reaching COMPLETE")
    return seen


def _endpoint_gone(r53r, endpoint_id):
    try:
        r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


def _rule_assoc_gone(r53r, assoc_id):
    try:
        r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


def _retry_dependency(fn, timeout_s=300.0, interval_s=10.0):
    """Retry fn() while a dependency is still being released asynchronously."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _teardown(ctx, st, name):
    """Ordered, waiting teardown: runs every step, then raises naming each one that failed.

    In band because the endpoint's service-managed ENIs must drain before subnet, group and VPC go.
    """
    if st.get("torn_down"):
        return st.get("leftovers", [])
    st["torn_down"] = True
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    r53 = ctx.client("route53")
    r53r = ctx.client("route53resolver")
    left = []

    steps: list = []

    def _try(label, fn):
        steps.append((label, fn))

    if st.get("rule_assoc"):
        _try("disassociate-resolver-rule", lambda: r53r.disassociate_resolver_rule(
            ResolverRuleId=st["rule"], VPCId=st["vpc"]))
        _try("await-rule-disassociated", lambda: _poll(
            lambda: _rule_assoc_gone(r53r, st["rule_assoc"]), lambda gone: gone,
            timeout_s=_TEARDOWN_TIMEOUT_S,
            what=f"resolver rule association {st['rule_assoc']} disappearing"))
    if st.get("rule"):
        _try("delete-resolver-rule", lambda: r53r.delete_resolver_rule(ResolverRuleId=st["rule"]))
    if st.get("instance"):
        _try("terminate-instance", lambda: ec2.terminate_instances(InstanceIds=[st["instance"]]))
    if st.get("endpoint"):
        _try("delete-resolver-endpoint",
             lambda: r53r.delete_resolver_endpoint(ResolverEndpointId=st["endpoint"]))
    if st.get("zone_id"):
        _try("delete-zone-records", lambda: r53.change_resource_record_sets(
            HostedZoneId=st["zone_id"],
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rr}
                                     for rr in st["records"]]}))
        _try("delete-hosted-zone", lambda: r53.delete_hosted_zone(Id=st["zone_id"]))
    if st.get("instance"):
        _try("await-instance-terminated", lambda: _poll(
            lambda: [i["State"]["Name"]
                     for r in ec2.describe_instances(
                         InstanceIds=[st["instance"]])["Reservations"] for i in r["Instances"]],
            lambda states: all(s == "terminated" for s in states),
            timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=10.0,
            what=f"instance {st['instance']} terminating"))
    if st.get("endpoint"):
        _try("await-resolver-endpoint-gone", lambda: _poll(
            lambda: _endpoint_gone(r53r, st["endpoint"]), lambda gone: gone,
            timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=10.0,
            what=f"resolver endpoint {st['endpoint']} disappearing"))
    for subnet in st.get("subnets", []):
        # An ENI still in the subnet makes DeleteSubnet impossible, and a resolver endpoint's ENIs
        # are service-managed: they leave when the endpoint is gone, not when it is asked to go.
        _try(f"await-eni-drain-{subnet}", lambda s=subnet: _poll(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [s]}])["NetworkInterfaces"],
            lambda enis: not enis, timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=10.0,
            what=f"subnet {s} draining its ENIs"))
    if st.get("profile"):
        _try("remove-role-from-profile", lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=st["profile"], RoleName=name))
        _try("delete-instance-profile",
             lambda: iam.delete_instance_profile(InstanceProfileName=st["profile"]))
    if st.get("role"):
        _try("detach-ssm-core",
             lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY))
        _try("delete-role", lambda: iam.delete_role(RoleName=name))
    if st.get("sg"):
        _try("delete-security-group",
             lambda: _retry_dependency(lambda: ec2.delete_security_group(GroupId=st["sg"])))
    for subnet in st.get("subnets", []):
        _try(f"delete-subnet-{subnet}", lambda s=subnet: ec2.delete_subnet(SubnetId=s))
    if st.get("igw"):
        _try("detach-igw", lambda: ec2.detach_internet_gateway(
            InternetGatewayId=st["igw"], VpcId=st["vpc"]))
        _try("delete-igw", lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"]))
    if st.get("vpc"):
        _try("delete-vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE:
                left.append(f"{label}: {exc.response.get('Error', {}).get('Code')}")
        except (AssertionError, WaiterError) as exc:
            left.append(f"{label}: {type(exc).__name__}: {str(exc)[:160]}")
    st["leftovers"] = left
    if left:
        found = sys.exc_info()[1]
        raise AssertionError((f"{found!r}; " if found else "")
                             + f"teardown could not remove everything the check created: {left!r}")
    return left


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """Revoking udp/53 on an inbound endpoint's security group stops udp answers while tcp/53 to the
    same address still resolves the record; restoring the rule brings the udp answer back.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    r53 = ctx.client("route53")
    r53r = ctx.client("route53resolver")

    name = ctx.unique_name("sim2real-r53r-sgd-")
    st = {}
    try:
        vpc_id = _build_network(ec2, ctx.region, name, st)
        ctx.on_cleanup(lambda: _teardown(ctx, st, name))

        endpoint_id = _resolver_endpoint(ctx, r53r, name, "INBOUND", st)
        instance_id, _private_ip = _launch_client(ec2, iam, ssm, name, st)
        zone = _private_zone(ctx, r53, vpc_id, st, [("db", _ZONE_RECORD_IP)])
        present = f"db.{zone}".rstrip(".")

        _await_running(ec2, instance_id)
        _await_agent(ssm, instance_id)
        statuses = _await_endpoint(r53r, endpoint_id)
        assert statuses[-1] == "OPERATIONAL", (
            f"the inbound endpoint never became OPERATIONAL; statuses seen were {statuses!r}")

        ips = sorted(a["Ip"] for a in _endpoint_ips(r53r, endpoint_id))
        assert ips, f"the inbound endpoint reported no addresses to query: {ips!r}"
        target = ips[0]
        # udp and tcp to the same address, for the same name, in one invocation: after the revoke
        # the second is the positive control for the first.
        probe = [(present, "A", target, "udp"),
                 (present, "A", target, "tcp")]

        # A poll, not a single query: a private hosted zone is not answered the instant
        # CreateHostedZone returns, and an early NXDOMAIN is negatively cached for as long as the
        # zone's SOA allows. BOTH protocols must be established, or the control proves nothing.
        before = _poll_dns(
            ssm, instance_id, probe, lambda g: all(bool(r["answers"]) for r in g),
            _DNS_CONVERGE_TIMEOUT_S,
            f"endpoint address {target} never answered {present} over both udp and tcp while both "
            f"were permitted, so there is no working setup to break", timeout=6.0)
        for result in before:
            assert result["rcode"] == "NOERROR", (
                f"the setup must be complete over both protocols before one of them is broken; "
                f"endpoint address {target} answered {result!r}")
            assert _rdata(result) == [_ZONE_RECORD_IP], (
                f"endpoint address {target} must serve the record this check wrote over every "
                f"protocol it listens on; it answered {result!r}")

        # Break exactly one thing; a security group denies by dropping, so the udp query times out.
        ec2.revoke_security_group_ingress(GroupId=st["sg"],
                                          IpPermissions=[_dns_permission(st["sg"], "udp")])
        remaining = ec2.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [st["sg"]]}])["SecurityGroupRules"]
        protocols = sorted(r["IpProtocol"] for r in remaining
                           if not r["IsEgress"] and r.get("FromPort") == 53)
        assert protocols == ["tcp"], (
            f"exactly one rule may have been removed -- udp/53 -- leaving tcp/53 in place; the "
            f"group's remaining port-53 ingress protocols are {protocols!r}")

        blocked = _poll_dns(
            ssm, instance_id, probe, lambda g: g[0]["rcode"] == "TIMEOUT",
            _DNS_CONVERGE_TIMEOUT_S,
            f"revoking udp/53 never stopped endpoint address {target} answering {present}, so the "
            f"security group is not enforced on the resolver endpoint's DNS listener",
            timeout=6.0)
        assert not blocked[0]["answers"], (
            f"a dropped query must carry no answer records; endpoint address {target} returned "
            f"{blocked[0]!r}")
        assert blocked[1]["rcode"] == "NOERROR", (
            f"the positive control must still hold: tcp/53 to the same endpoint address is still "
            f"permitted, so the identical query must still be answered there; it answered "
            f"{blocked[1]!r}")
        assert _rdata(blocked[1]) == [_ZONE_RECORD_IP], (
            f"the endpoint and the name must be unaffected -- only the protocol the security group "
            f"carries changed; the tcp query answered {blocked[1]!r}")

        # Restore the single rule; the identical query must succeed again.
        ec2.authorize_security_group_ingress(GroupId=st["sg"],
                                            IpPermissions=[_dns_permission(st["sg"], "udp")])
        after = _poll_dns(
            ssm, instance_id, probe, lambda g: g[0]["rcode"] == "NOERROR",
            _DNS_CONVERGE_TIMEOUT_S,
            f"restoring udp/53 never brought endpoint address {target} back for {present}",
            timeout=6.0)
        assert _rdata(after[0]) == [_ZONE_RECORD_IP], (
            f"once udp/53 is permitted again the endpoint must serve the same record it served "
            f"before; it answered {after[0]!r}")
        assert _rdata(after[1]) == [_ZONE_RECORD_IP], (
            f"the control must be unchanged throughout, since tcp/53 was never revoked; it "
            f"answered {after[1]!r}")
    finally:
        _teardown(ctx, st, name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
