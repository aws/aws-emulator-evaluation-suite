"""vpc-name-resolution-dhcp-black-hole-nameserver-fails-guest-lookups-while-default-resolves."""
from __future__ import annotations

import ipaddress
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-name-resolution-dhcp-black-hole-nameserver-fails-guest-lookups-while-default-resolves"
GROUP = "dhcp-options-dns-data-plane"
SERVICES = ["ec2"]

#: Treatment and control are twins that differ ONLY in the DHCP option set associated with the VPC.
_SIDES = {
    "treatment": {"vpc": "10.81.0.0/16", "subnet": "10.81.1.0/24"},
    "control": {"vpc": "10.82.0.0/16", "subnet": "10.82.1.0/24"},
}
#: Inside the treatment VPC's CIDR but outside its only subnet: no ENI can ever hold it, so a
#: query sent there is dropped by the VPC fabric and never answered.
_BLACK_HOLE = "10.81.200.53"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
#: Control channel only. Each VPC gets its own three endpoints, and the guest pins their ENI
#: addresses in /etc/hosts via user data, so SSM works even where DHCP-supplied DNS is a black hole.
_SSM_ENDPOINT_SERVICES = ("ssm", "ssmmessages", "ec2messages")
_SSM_ONLINE_TIMEOUT_S = 720
_PHASE_TIMEOUT_S = 240


def _default_domain(region):
    """AWS's documented default `domain-name` for the AmazonProvidedDNS option set."""
    return "ec2.internal" if region == "us-east-1" else f"{region}.compute.internal"


def _resolver_ip(vpc_cidr):
    """The Amazon-provided resolver sits at the VPC's base address plus two."""
    return str(ipaddress.ip_network(vpc_cidr).network_address + 2)


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
    """A DHCP option set with a black-hole `domain-name-servers`, associated before launch, makes
    in-guest lookups fail while a twin VPC on AmazonProvidedDNS resolves the same name, and the
    treatment guest still reaches the VPC +2 resolver directly: the DHCP-supplied config is the cause."""
    st: dict = {"sides": {}, "sgs": [], "instances": [], "endpoints": [], "subnets": [],
                "vpcs": [], "dopts": []}
    try:
        _build(ctx, st)
        _arms(ctx, st)
    finally:
        # In-band: two instances, six endpoints and two ENI drains exceed the cleanup budget.
        _teardown(ctx, st)


# ===== the fixture ==========================================================
def _build(ctx, st) -> None:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-vpcdns-dhcp-")
    st["name"] = name
    st["suffix"] = name.lower().replace("_", "-") + ".internal"
    zone = _usable_zones(ec2, 1)[0]

    configs = {
        "treatment": [{"Key": "domain-name", "Values": [st["suffix"]]},
                      {"Key": "domain-name-servers", "Values": [_BLACK_HOLE]}],
        "control": [{"Key": "domain-name", "Values": [_default_domain(ctx.region)]},
                    {"Key": "domain-name-servers", "Values": ["AmazonProvidedDNS"]}],
    }

    for side, cidrs in _SIDES.items():
        s = st["sides"].setdefault(side, {})
        dopt = ec2.create_dhcp_options(
            DhcpConfigurations=configs[side],
            TagSpecifications=[{"ResourceType": "dhcp-options",
                                "Tags": _tags_for(f"{name}-{side}")}],
        )["DhcpOptions"]["DhcpOptionsId"]
        s["dopt"] = dopt
        st["dopts"].append(dopt)
        _backstop(ctx, lambda d=dopt: ec2.delete_dhcp_options(DhcpOptionsId=d))

        vpc_id = ec2.create_vpc(
            CidrBlock=cidrs["vpc"],
            TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(f"{name}-{side}")}],
        )["Vpc"]["VpcId"]
        s["vpc"] = vpc_id
        st["vpcs"].append(vpc_id)
        _backstop(ctx, lambda v=vpc_id: ec2.delete_vpc(VpcId=v))
        ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
        # Associated BEFORE any instance exists, so the first DHCP lease carries it.
        ec2.associate_dhcp_options(DhcpOptionsId=dopt, VpcId=vpc_id)

        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=cidrs["subnet"], AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(f"{name}-{side}")}],
        )["Subnet"]["SubnetId"]
        s["subnet"] = subnet_id
        st["subnets"].append(subnet_id)
        _backstop(ctx, lambda sn=subnet_id: ec2.delete_subnet(SubnetId=sn))

        host_sg = _create_sg(ctx, ec2, st, vpc_id, f"{name}-{side}-host", "sim2real vpcdns host")
        endpoint_sg = _create_sg(ctx, ec2, st, vpc_id, f"{name}-{side}-endpoint",
                                 "sim2real vpcdns endpoints")
        s["host_sg"] = host_sg
        ec2.authorize_security_group_ingress(
            GroupId=endpoint_sg,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                            "UserIdGroupPairs": [{"GroupId": host_sg}]}])
        s["endpoints"] = {}
        for service in _SSM_ENDPOINT_SERVICES:
            endpoint_id = ec2.create_vpc_endpoint(
                VpcId=vpc_id, VpcEndpointType="Interface",
                ServiceName=f"com.amazonaws.{ctx.region}.{service}",
                SubnetIds=[subnet_id], SecurityGroupIds=[endpoint_sg], PrivateDnsEnabled=True,
                TagSpecifications=[{"ResourceType": "vpc-endpoint",
                                    "Tags": _tags_for(f"{name}-{side}-{service}")}],
            )["VpcEndpoint"]["VpcEndpointId"]
            st["endpoints"].append(endpoint_id)
            s["endpoints"][service] = endpoint_id
            _backstop(ctx, lambda e=endpoint_id: ec2.delete_vpc_endpoints(VpcEndpointIds=[e]))

    # The association is stored and echoed back before anything launches.
    for side, s in st["sides"].items():
        vpc = ec2.describe_vpcs(VpcIds=[s["vpc"]])["Vpcs"][0]
        assert vpc["DhcpOptionsId"] == s["dopt"], (
            f"{side} VPC reports DhcpOptionsId {vpc['DhcpOptionsId']!r}, associated {s['dopt']!r}")
        stored = {c["Key"]: sorted(v["Value"] for v in c["Values"]) for c in
                  ec2.describe_dhcp_options(DhcpOptionsIds=[s["dopt"]])["DhcpOptions"][0][
                      "DhcpConfigurations"]}
        want = {c["Key"]: sorted(c["Values"]) for c in configs[side]}
        assert stored == want, f"{side} option set echoes {stored!r}, created with {want!r}"

    role_name = name + "-role"
    st["role"] = role_name
    st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]

    for side, s in st["sides"].items():
        pins = {}
        for service, endpoint_id in s["endpoints"].items():
            ep = _poll(lambda e=endpoint_id: _endpoint(ec2, e), lambda e: e["State"] == "available",
                       timeout_s=600, interval_s=10, what=f"{side} {service} endpoint available")
            eni = ec2.describe_network_interfaces(
                NetworkInterfaceIds=ep["NetworkInterfaceIds"])["NetworkInterfaces"][0]
            pins[f"{service}.{ctx.region}.amazonaws.com"] = eni["PrivateIpAddress"]
        s["instance"] = _launch(ctx, ec2, st, ami, s["host_sg"], s["subnet"],
                                f"{name}-{side}", _user_data(pins))

    for side, s in st["sides"].items():
        info = _poll(lambda i=s["instance"]: _agent_view(ssm, i),
                     lambda v: v is not None and v.get("PingStatus") == "Online",
                     timeout_s=_SSM_ONLINE_TIMEOUT_S, interval_s=10,
                     what=f"the SSM agent on the {side} instance {s['instance']} coming Online")
        assert info["PingStatus"] == "Online", f"{side} agent view was {info!r}"


def _user_data(pins) -> str:
    """Identical on both sides apart from the addresses: pin the SSM control-channel hostnames to
    this VPC's endpoint ENIs, then restart the agent so it re-resolves. The name the arms resolve
    is never pinned."""
    lines = "\n".join(f"{ip} {host}" for host, ip in sorted(pins.items()))
    return ("#!/bin/bash\n"
            f"cat >> /etc/hosts <<'EOF'\n{lines}\nEOF\n"
            "systemctl restart amazon-ssm-agent\n")


# ===== the arms =============================================================
def _arms(ctx, st) -> None:
    ssm = ctx.client("ssm")
    target = f"ec2.{ctx.region}.amazonaws.com"
    readings = {}
    for side, s in st["sides"].items():
        readings[side] = _probe(ssm, s["instance"], target,
                                _resolver_ip(_SIDES["treatment"]["vpc"] if side == "treatment"
                                             else _SIDES["control"]["vpc"]))
        assert readings[side]["iid"] == s["instance"], (
            f"{side} guest read instance id {readings[side]['iid']!r}, expected {s['instance']!r}")

    t, c = readings["treatment"], readings["control"]
    t_resolver = _resolver_ip(_SIDES["treatment"]["vpc"])
    c_resolver = _resolver_ip(_SIDES["control"]["vpc"])
    default_domain = _default_domain(ctx.region)

    # --- the guest resolver configuration came from DHCP ------------------------------------
    assert t["nameservers"] == [_BLACK_HOLE], (
        f"treatment guest's upstream nameservers are {t['nameservers']!r}; the associated option "
        f"set hands out only {_BLACK_HOLE!r}. resolv files: {t['resolv_files']!r}")
    assert st["suffix"] in t["search"], (
        f"treatment guest's search list {t['search']!r} lacks the option set's domain-name "
        f"{st['suffix']!r}. /etc/resolv.conf: {t['etc_resolv'][:400]!r}")
    assert c["nameservers"] == [c_resolver], (
        f"control guest's upstream nameservers are {c['nameservers']!r}; AmazonProvidedDNS in "
        f"{_SIDES['control']['vpc']} is {c_resolver!r}. resolv files: {c['resolv_files']!r}")
    assert default_domain in c["search"], (
        f"control guest's search list {c['search']!r} lacks the default domain {default_domain!r}")
    assert st["suffix"] not in c["search"] and _BLACK_HOLE not in c["nameservers"], (
        f"the control guest carries treatment configuration: search={c['search']!r} "
        f"nameservers={c['nameservers']!r}")

    # --- resolution through the system resolver ---------------------------------------------
    assert c["getent_rc"] == 0 and c["getent_addrs"], (
        f"control guest could not resolve {target!r} through AmazonProvidedDNS: "
        f"rc={c['getent_rc']!r} out={c['getent_out'][:300]!r}")
    assert all(ipaddress.ip_address(a).version == 4 for a in c["getent_addrs"]), (
        f"control guest resolved {target!r} to {c['getent_addrs']!r}")
    assert t["getent_rc"] != 0, (
        f"treatment guest resolved {target!r} (to {t['getent_addrs']!r}) although its only "
        f"DHCP-supplied nameserver {_BLACK_HOLE!r} never answers")
    assert t["getent_addrs"] == [], (
        f"treatment guest's failed lookup still produced addresses {t['getent_addrs']!r}")

    # --- raw queries: the black hole never answers; the Amazon resolver path is intact ------
    assert t["raw_black_hole"]["answered"] is False, (
        f"the black-hole address {_BLACK_HOLE!r} answered a DNS query: {t['raw_black_hole']!r}")
    assert t["raw_vpc_resolver"]["answered"] is True and t["raw_vpc_resolver"]["a"], (
        f"positive control: a raw query from the treatment guest to its VPC resolver "
        f"{t_resolver!r} must be answered with A records - otherwise the failed lookup could be a "
        f"broken network path rather than the DHCP configuration: {t['raw_vpc_resolver']!r}")
    assert t["raw_vpc_resolver"]["rcode"] == 0 and t["raw_vpc_resolver"]["id_ok"], (
        f"treatment raw query to {t_resolver!r} returned {t['raw_vpc_resolver']!r}")
    assert c["raw_vpc_resolver"]["answered"] is True and c["raw_vpc_resolver"]["a"], (
        f"control raw query to {c_resolver!r} returned {c['raw_vpc_resolver']!r}")


def _probe(ssm, instance_id, target, vpc_resolver) -> dict:
    inv = _run_phase(ssm, instance_id, _probe_script(target, vpc_resolver))
    assert inv["ResponseCode"] == 0, (
        f"the probe script failed on {instance_id} (status={inv['Status']!r} "
        f"rc={inv['ResponseCode']!r}): stderr={inv['StandardErrorContent'][:400]!r}")
    return _payload_json(inv)


def _probe_script(target, vpc_resolver) -> str:
    cfg = json.dumps({"target": target, "vpc_resolver": vpc_resolver, "black_hole": _BLACK_HOLE})
    return """set -uo pipefail
python3 - <<'PYEOF'
import json, os, random, socket, struct, subprocess, urllib.request
CFG = json.loads('__CFG__')
treq = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                              headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"})
token = urllib.request.urlopen(treq, timeout=5).read().decode()
req = urllib.request.Request("http://169.254.169.254/latest/meta-data/instance-id",
                             headers={"X-aws-ec2-metadata-token": token})
out = {"iid": urllib.request.urlopen(req, timeout=5).read().decode()}
def read(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return None
files = {p: read(p) for p in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf")}
out["resolv_files"] = files
out["etc_resolv"] = files["/etc/resolv.conf"] or ""
upstream = files["/run/systemd/resolve/resolv.conf"] or files["/etc/resolv.conf"] or ""
out["nameservers"] = [ln.split()[1] for ln in upstream.splitlines()
                      if ln.startswith("nameserver") and len(ln.split()) > 1]
search = []
for text in files.values():
    for ln in (text or "").splitlines():
        if ln.startswith("search") or ln.startswith("domain"):
            search += ln.split()[1:]
out["search"] = sorted(set(search))
try:
    r = subprocess.run(["timeout", "45", "getent", "ahostsv4", CFG["target"]],
                       capture_output=True, text=True, timeout=60)
    out["getent_rc"], out["getent_out"] = r.returncode, r.stdout
except subprocess.TimeoutExpired:
    out["getent_rc"], out["getent_out"] = 124, ""
out["getent_addrs"] = sorted({ln.split()[0] for ln in out["getent_out"].splitlines() if ln.strip()})
def skip(data, off):
    while True:
        n = data[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += n + 1
def query(server, name):
    tid = random.randint(0, 65535)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    pkt += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\\0"
    pkt += struct.pack(">HH", 1, 1)
    for _ in range(2):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(pkt, (server, 53))
            data, _ = s.recvfrom(4096)
        except OSError:
            continue
        finally:
            s.close()
        rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        off = skip(data, 12) + 4
        addrs = []
        for _ in range(an):
            off = skip(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4:
                addrs.append(socket.inet_ntoa(data[off:off + 4]))
            off += rdlen
        return {"answered": True, "id_ok": rid == tid, "rcode": flags & 0xF, "a": sorted(addrs)}
    return {"answered": False, "id_ok": False, "rcode": None, "a": []}
out["raw_vpc_resolver"] = query(CFG["vpc_resolver"], CFG["target"])
out["raw_black_hole"] = query(CFG["black_hole"], CFG["target"])
print(json.dumps(out))
PYEOF
""".replace("__CFG__", cfg)


# ===== in-band teardown =====================================================
def _teardown(ctx, st) -> None:
    """Run every delete in order, collect each failure that is not a not-found, then raise them."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    steps: list = []
    if st.get("endpoints"):
        steps.append(("endpoints", lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=st["endpoints"])))
    if st.get("instances"):
        steps.append(("instances", lambda: _terminate_and_wait(ec2, st["instances"])))
    if st.get("profile"):
        steps.append(("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"])))
    if st.get("role"):
        steps.append(("role", lambda: _drop_role(iam, st["role"])))
    for vpc_id in st.get("vpcs", []):
        steps.append((f"eni-drain {vpc_id}", lambda v=vpc_id: _poll(
            lambda: _vpc_enis(ec2, v), lambda enis: enis == [],
            timeout_s=600, interval_s=2, what=f"every ENI in {v!r} draining")))
    for sg in reversed(st.get("sgs", [])):
        steps.append((f"sg-rules {sg}", lambda s=sg: _revoke_all(ec2, s)))
    for sg in reversed(st.get("sgs", [])):
        steps.append((f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s))))
    for subnet in st.get("subnets", []):
        steps.append((f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s))))
    for vpc_id in st.get("vpcs", []):
        steps.append((f"vpc {vpc_id}", lambda v=vpc_id: _retry_dependency(lambda: ec2.delete_vpc(VpcId=v))))
    for dopt in st.get("dopts", []):
        steps.append((f"dhcp-options {dopt}", lambda d=dopt: _retry_dependency(
            lambda: ec2.delete_dhcp_options(DhcpOptionsId=d))))
    for vpc_id in st.get("vpcs", []):
        steps.append((f"vpc-gone {vpc_id}", lambda v=vpc_id: _vpc_still_there(ec2, v)))
    left: list = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 - collected, then raised below
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


def _vpc_still_there(ec2, vpc_id):
    """Raise unless DescribeVpcs reports the VPC gone (its InvalidVpcID.NotFound is a gone code)."""
    still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    raise AssertionError(f"vpc {vpc_id} is still describable: {still!r}")


# ===== helpers ==============================================================
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidVpcEndpointId.NotFound", "InvalidPermission.NotFound",
               "InvalidDhcpOptionID.NotFound", "InvalidDhcpOptionsID.NotFound")


def _backstop(ctx, fn):
    """Register *fn* as a backup of the in-band teardown: a `_GONE_CODES` not-found means the
    teardown already removed the resource; any other error raises."""
    def _run():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise
    ctx.on_cleanup(_run)


def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "vpcdns-dhcp-black-hole"},
            {"Key": "sim2real:managed", "Value": "true"}]


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=5.0):
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


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _retry_dependency(fn, timeout_s=300, interval_s=10, codes=("DependencyViolation",)):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _usable_zones(ec2, want):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= want, (
        f"need {want} available AZs offering {_INSTANCE_TYPE}; offerings {sorted(offered)!r}, "
        f"usable {usable!r}")
    return usable[:want]


def _create_sg(ctx, ec2, st, vpc_id, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    _backstop(ctx, lambda: ec2.delete_security_group(GroupId=sg))
    return sg


def _revoke_all(ec2, sg):
    group = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]
    if group.get("IpPermissions"):
        ec2.revoke_security_group_ingress(GroupId=sg, IpPermissions=group["IpPermissions"])


def _endpoint(ec2, endpoint_id):
    return ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]


def _vpc_enis(ec2, vpc_id):
    return [e["NetworkInterfaceId"] for e in ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]]


def _launch(ctx, ec2, st, ami, sg, subnet_id, tag_name, user_data):
    instance_id = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg],
                                "AssociatePublicIpAddress": False}],
            IamInstanceProfile={"Name": st["profile"]},
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            UserData=user_data,
            TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                               for rt in ("instance", "volume")],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )["Instances"][0]["InstanceId"]
    st["instances"].append(instance_id)
    _backstop(ctx, lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    return instance_id


def _terminate_and_wait(ec2, instance_ids, timeout_s=600):
    ec2.terminate_instances(InstanceIds=list(instance_ids))
    _poll(lambda: [i["State"]["Name"]
                   for r in _call_with_retry(
                       lambda: ec2.describe_instances(InstanceIds=list(instance_ids)),
                       codes=_THROTTLE + ("InvalidInstanceID.NotFound",),
                       retries=12, delay=5.0)["Reservations"]
                   for i in r["Instances"]],
          lambda states: all(s == "terminated" for s in states),
          timeout_s=timeout_s, interval_s=10,
          what=f"instances {list(instance_ids)!r} reaching terminated")


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real vpcdns dhcp hosts",
                    Tags=[{"Key": "sim2real", "Value": "vpcdns-dhcp-black-hole"}])
    _backstop(ctx, lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    _backstop(ctx, lambda: iam.detach_role_policy(RoleName=role_name,
                                                  PolicyArn=_SSM_CORE_POLICY))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "vpcdns-dhcp-black-hole"}])
    _backstop(ctx, lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    _backstop(ctx, lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name))
    # IAM exposes no "usable" condition; RunInstances' bounded retry on InvalidParameterValue in
    # _launch is what makes this correct -- no sleep here.


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(10):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 9:
                raise
            time.sleep(5)
    iam.delete_instance_profile(InstanceProfileName=profile_name)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    for attempt in range(10):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DeleteConflict" and attempt < 9:
                time.sleep(5)
                continue
            raise


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]):
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _run_phase(ssm, instance_id, script, timeout_s=_PHASE_TIMEOUT_S):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=300, Comment=CHECK[:100]))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=5.0,
                 what=f"invocation {command_id} on {instance_id} reaching a terminal status")


def _payload_json(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout at all: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
