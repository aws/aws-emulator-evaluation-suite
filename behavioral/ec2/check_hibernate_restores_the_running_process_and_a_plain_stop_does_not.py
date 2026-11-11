"""hibernate-restores-the-running-process-and-a-plain-stop-does-not."""
from __future__ import annotations

import json
import socket
import sys
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hibernate-restores-the-running-process-and-a-plain-stop-does-not"
GROUP = "instance-lifecycle"
SERVICES = ["ec2"]

_VPC_CIDR = "10.80.0.0/16"
_SUBNET_CIDR = "10.80.1.0/24"
_AGENT_PORT = 8080
_INSTANCE_TYPE = "t3.micro"
_ROOT_GIB = 12
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_CONNECT_TIMEOUT_S = 8.0
_AGENT_TIMEOUT_S = 1200.0
_REASON_HIBERNATE = "Client.UserInitiatedHibernate"
_REASON_SHUTDOWN = "Client.UserInitiatedShutdown"
_GONE_CODES = (
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidGroup.NotFound",
    "InvalidInstanceID.NotFound",
    "InvalidRouteTableID.NotFound",
    "InvalidInternetGatewayID.NotFound",
    "InvalidAssociationID.NotFound",
    "Gateway.NotAttached",
)
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Two identical instances stopped together, one with Hibernate=True, come back differently: the
    hibernated guest resumes the same process, boot id and counter, the plainly stopped one boots
    anew, and EC2 gives the two stops different StateReason codes. Only memory tells them apart."""
    ec2 = ctx.client("ec2")
    st: dict = {"instances": [], "sgs": [], "subnets": [], "rtbs": [], "assocs": [], "igws": []}
    try:
        _build(ctx, ec2, st)
        _legs(ctx, ec2, st)
    finally:
        _teardown(ec2, st)


# ===== the legs ==============================================================


def _legs(ctx, ec2, st) -> None:
    hib, plain = st["hibernate"], st["plain"]

    # --- the barrier: BOTH guests are up and are this run's guests ---
    before = {}
    for label, iid in (("hibernated", hib), ("plainly-stopped", plain)):
        ip = st["ip"][iid]
        view = _poll(
            lambda ip=ip: _agent(ctx, ip, "/state"),
            lambda r: r.get("nonce") == st["nonce"],
            timeout_s=_AGENT_TIMEOUT_S, interval_s=15.0,
            what=(f"{DATAPLANE_MARKER}: the {label} guest's agent on {ip}:{_AGENT_PORT} answering "
                  f"with the nonce {st['nonce']!r}"),
        )
        for field in ("session", "boot_id", "counter", "uptime_s"):
            assert view.get(field) not in (None, ""), (
                f"{DATAPLANE_MARKER}: the {label} guest must report {field!r} before anything is "
                f"stopped, or the comparison after the restart proves nothing: {view!r}"
            )
        before[iid] = view

    assert before[hib]["session"] != before[plain]["session"], (
        f"the two guests must be distinct processes to start with; both reported session "
        f"{before[hib]['session']!r}"
    )
    assert before[hib]["boot_id"] != before[plain]["boot_id"], (
        f"the two guests must be distinct kernel boots to start with; both reported boot_id "
        f"{before[hib]['boot_id']!r}"
    )
    # let the counter advance, so "carried on" is a strictly-greater claim rather than an equality
    advanced = _poll(
        lambda: _agent(ctx, st["ip"][hib], "/state"),
        lambda r: r.get("nonce") == st["nonce"]
        and int(r.get("counter", -1)) > int(before[hib]["counter"]),
        timeout_s=120.0, interval_s=5.0,
        what=(f"{DATAPLANE_MARKER}: the hibernation candidate's in-memory counter advancing past "
              f"{before[hib]['counter']!r} while it is running"),
    )
    before[hib] = advanced

    # --- the two stops, seconds apart, differing in exactly one flag ---
    # EC2 refuses StopInstances(Hibernate=True) with UnsupportedOperation ("not ready to
    # hibernate yet, retry in a few minutes") for a period after launch; there is no queryable
    # readiness field, so the refusal itself is the poll's negative outcome.
    hib_resp = _stop_hibernate_when_ready(ec2, hib)["StoppingInstances"]
    plain_resp = ec2.stop_instances(InstanceIds=[plain])["StoppingInstances"]
    assert hib_resp[0]["CurrentState"]["Name"] == "stopping", (
        f"StopInstances(Hibernate=True) must report the transient 'stopping' state, got "
        f"{hib_resp[0]!r}"
    )
    assert plain_resp[0]["CurrentState"]["Name"] == "stopping", (
        f"StopInstances must report the transient 'stopping' state, got {plain_resp[0]!r}"
    )
    for label, iid in (("hibernated", hib), ("plainly-stopped", plain)):
        _poll(lambda i=iid: _state(ec2, i), lambda s: s == "stopped",
              timeout_s=900.0, interval_s=10.0,
              what=f"{STATE_MARKER}: the {label} instance {iid} reaching 'stopped'")

    # --- the control plane distinguishes them, in the same instant ---
    hib_reason = _describe(ec2, hib).get("StateReason", {})
    plain_reason = _describe(ec2, plain).get("StateReason", {})
    assert hib_reason.get("Code") == _REASON_HIBERNATE, (
        f"the hibernated instance {hib} must be attributed to {_REASON_HIBERNATE!r}; "
        f"DescribeInstances reports {hib_reason!r}"
    )
    assert plain_reason.get("Code") == _REASON_SHUTDOWN, (
        f"the plainly stopped twin {plain} must be attributed to {_REASON_SHUTDOWN!r} — a target "
        f"that reports the same reason for both has not modelled hibernation at all; "
        f"DescribeInstances reports {plain_reason!r}"
    )
    hib_block = _describe(ec2, hib).get("HibernationOptions", {})
    assert hib_block.get("Configured") is True, (
        f"the hibernated instance must still report HibernationOptions.Configured True, got "
        f"{hib_block!r}"
    )

    # --- start both, and read the guests again ---
    ec2.start_instances(InstanceIds=[hib])
    ec2.start_instances(InstanceIds=[plain])
    after = {}
    for label, iid in (("hibernated", hib), ("plainly-stopped", plain)):
        _poll(lambda i=iid: _state(ec2, i), lambda s: s == "running",
              timeout_s=900.0, interval_s=10.0,
              what=f"{STATE_MARKER}: the {label} instance {iid} reaching 'running' again")
        # A hibernated instance keeps its private IPv4 address; a stopped one does too. The public
        # address is re-assigned on both, so it is re-read rather than assumed.
        inst = _poll(lambda i=iid: _describe(ec2, i),
                     lambda i: i is not None and bool(i.get("PublicIpAddress")),
                     timeout_s=300.0, interval_s=5.0,
                     what=f"the {label} instance {iid} being given a public IPv4 address again")
        assert inst["PrivateIpAddress"] == st["private_ip"][iid], (
            f"the {label} instance must retain its private IPv4 address "
            f"{st['private_ip'][iid]!r}, got {inst['PrivateIpAddress']!r}"
        )
        ip = inst["PublicIpAddress"]
        after[iid] = _poll(
            lambda ip=ip: _agent(ctx, ip, "/state"),
            lambda r: r.get("nonce") == st["nonce"],
            timeout_s=_AGENT_TIMEOUT_S, interval_s=15.0,
            what=(f"{DATAPLANE_MARKER}: the {label} guest's agent answering again on {ip} after "
                  f"the restart"),
        )

    # --- the hibernated guest is the SAME process on the SAME kernel boot ---
    assert after[hib]["boot_id"] == before[hib]["boot_id"], (
        f"hibernation reloads the RAM contents, so the kernel boot id must be unchanged: expected "
        f"{before[hib]['boot_id']!r}, got {after[hib]['boot_id']!r} — a differing boot id means the "
        f"guest was rebooted, which is a plain stop wearing hibernation's name"
    )
    assert after[hib]["session"] == before[hib]["session"], (
        f"the process running before hibernation must be resumed, so its per-process UUID must be "
        f"unchanged: expected {before[hib]['session']!r}, got {after[hib]['session']!r}"
    )
    assert int(after[hib]["counter"]) >= int(before[hib]["counter"]), (
        f"the resumed process's in-memory counter must carry on from where it was, not restart: it "
        f"was {before[hib]['counter']!r} before hibernation and is {after[hib]['counter']!r} after"
    )
    assert float(after[hib]["uptime_s"]) >= float(before[hib]["uptime_s"]), (
        f"the resumed process's own monotonic age must not go backwards: {before[hib]['uptime_s']!r}"
        f" -> {after[hib]['uptime_s']!r}"
    )
    assert after[hib]["shm"] == before[hib]["shm"], (
        f"the RAM-backed tmpfs file written before hibernation must still hold the same bytes: "
        f"expected {before[hib]['shm']!r}, got {after[hib]['shm']!r}"
    )

    # --- the plain twin is a NEW process on a NEW kernel boot: the same read, opposite verdict ---
    assert after[plain]["boot_id"] != before[plain]["boot_id"], (
        f"a plain stop clears RAM, so the twin must come back on a NEW kernel boot; it reported the "
        f"same boot_id {before[plain]['boot_id']!r} both times — which would mean the plain stop "
        f"preserved memory it must not preserve"
    )
    assert after[plain]["session"] != before[plain]["session"], (
        f"a plain stop must give the twin a NEW agent process; it reported the same session "
        f"{before[plain]['session']!r} both times"
    )
    assert after[plain]["shm"] != before[plain]["shm"], (
        f"the twin's RAM-backed tmpfs file must be regenerated after a plain stop; it still held "
        f"{before[plain]['shm']!r}"
    )
    # and the crossing assertion the whole check exists for
    assert after[hib]["boot_id"] == before[hib]["boot_id"] \
        and after[plain]["boot_id"] != before[plain]["boot_id"], (
        f"the ONLY difference between these two instances was Hibernate=True, so exactly one of "
        f"them must have kept its kernel boot: hibernated "
        f"{before[hib]['boot_id']!r} -> {after[hib]['boot_id']!r}, plain "
        f"{before[plain]['boot_id']!r} -> {after[plain]['boot_id']!r}"
    )


# ===== the fixture ===========================================================


def _build(ctx, ec2, st) -> None:
    """A public subnet and TWO identically configured hibernation-enabled instances, all of this
    check's own making — nothing depends on an ambient default VPC."""
    name = ctx.unique_name("sim2real-b1hib-")
    st["name"] = name
    st["nonce"] = "sim2real-nonce-" + uuid.uuid4().hex
    st["ip"] = {}
    st["private_ip"] = {}

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    az = sorted(_zones_offering(ec2, _INSTANCE_TYPE))[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                        "InvalidSubnetID.NotFound"))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(name)}],
    )["InternetGateway"]["InternetGatewayId"]
    st["igws"].append(igw_id)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(name)}],
    )["RouteTable"]["RouteTableId"]
    st["rtbs"].append(rtb_id)
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    st["assocs"].append(
        ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
    )

    sg_id = ec2.create_security_group(
        GroupName=name + "-agent", VpcId=vpc_id,
        Description="sim2real hibernation check: reaches the guests state agents",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg_id)
    # The agent returns only opaque per-process identifiers and a counter — no credentials, no
    # metadata, nothing an observer could use. Only the runner's ingress ranges are admitted.
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _AGENT_PORT, "ToPort": _AGENT_PORT,
                        "IpRanges": [{"CidrIp": c, "Description": "sim2real hibernation state agent"}
                                      for c in ctx.ingress_cidrs()]}],
    )

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    images = ec2.describe_images(ImageIds=[ami])["Images"]
    assert len(images) == 1, f"expected exactly one image for {ami!r}, got {images!r}"
    root_device = images[0]["RootDeviceName"]

    for key in ("hibernate", "plain"):
        instance = ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            UserData=_user_data(st["nonce"]),
            # Hibernation requires an ENCRYPTED root volume with room for the RAM image. BOTH
            # instances are configured identically, including the plain twin, so the only difference
            # between the two arms is the Hibernate flag on StopInstances.
            HibernationOptions={"Configured": True},
            BlockDeviceMappings=[{
                "DeviceName": root_device,
                "Ebs": {"VolumeSize": _ROOT_GIB, "VolumeType": "gp3", "Encrypted": True,
                        "DeleteOnTermination": True},
            }],
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": _tags_for(f"{name}-{key}")},
                {"ResourceType": "volume", "Tags": _tags_for(f"{name}-{key}")},
            ],
        )["Instances"][0]
        instance_id = instance["InstanceId"]
        st[key] = instance_id
        st["instances"].append(instance_id)
        ctx.on_cleanup(lambda i=instance_id: ec2.terminate_instances(InstanceIds=[i]))

    for key in ("hibernate", "plain"):
        instance_id = st[key]
        _poll(lambda i=instance_id: _state(ec2, i), lambda s: s == "running",
              timeout_s=900.0, interval_s=10.0,
              what=f"{STATE_MARKER}: instance {instance_id} ({key}) reaching 'running'")
        inst = _poll(lambda i=instance_id: _describe(ec2, i),
                     lambda i: i is not None and bool(i.get("PublicIpAddress")),
                     timeout_s=300.0, interval_s=5.0,
                     what=f"instance {instance_id} being given a public IPv4 address")
        st["ip"][instance_id] = inst["PublicIpAddress"]
        st["private_ip"][instance_id] = inst["PrivateIpAddress"]
        configured = inst.get("HibernationOptions", {})
        assert configured.get("Configured") is True, (
            f"instance {instance_id} was launched with HibernationOptions.Configured True and must "
            f"report it; DescribeInstances says {configured!r}"
        )
        root = [m for m in inst["BlockDeviceMappings"] if m["DeviceName"] == root_device]
        assert len(root) == 1, (
            f"instance {instance_id} must report a mapping for its root device {root_device!r}, got "
            f"{inst['BlockDeviceMappings']!r}"
        )
        volume = ec2.describe_volumes(VolumeIds=[root[0]["Ebs"]["VolumeId"]])["Volumes"][0]
        assert volume["Encrypted"] is True, (
            f"hibernation requires an encrypted root volume; {volume['VolumeId']} on "
            f"{instance_id} reports {volume!r}"
        )
        assert volume["Size"] == _ROOT_GIB, (
            f"the root volume must be the {_ROOT_GIB} GiB this check asked for, so there is room "
            f"for the RAM image; got {volume!r}"
        )


def _user_data(nonce: str) -> str:
    """Install the state agent as a systemd unit enabled at boot.

    A unit rather than a background `nohup`, deliberately: cloud-init user data runs ONCE per
    instance, so a backgrounded process would never come back on the plainly stopped twin and the
    twin control would have nothing to report. A unit restarts on the twin's fresh boot and is left
    untouched on the hibernated instance, because that process never stopped.
    """
    agent = _AGENT_SOURCE.replace("__NONCE__", nonce)
    return (
        "#!/bin/bash\n"
        "set -x\n"
        "mkdir -p /opt/sim2real\n"
        "cat > /opt/sim2real/agent.py <<'SIM2REAL_AGENT_EOF'\n"
        f"{agent}"
        "SIM2REAL_AGENT_EOF\n"
        "cat > /etc/systemd/system/sim2real-agent.service <<'SIM2REAL_UNIT_EOF'\n"
        "[Unit]\n"
        "Description=sim2real hibernation state agent\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "ExecStart=/usr/bin/python3 /opt/sim2real/agent.py\n"
        "Restart=always\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
        "SIM2REAL_UNIT_EOF\n"
        "systemctl daemon-reload\n"
        "systemctl enable --now sim2real-agent.service\n"
    )


_AGENT_SOURCE = f'''\
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

NONCE = "__NONCE__"
#: Minted in THIS process. It survives a hibernate/resume and cannot survive a reboot.
SESSION = uuid.uuid4().hex
STARTED = time.monotonic()
SHM_PATH = "/dev/shm/sim2real-ram"
COUNTER = {{"n": 0}}

with open(SHM_PATH, "w") as fh:
    fh.write(SESSION + ":" + uuid.uuid4().hex)


def tick():
    while True:
        COUNTER["n"] += 1
        time.sleep(1.0)


def read(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError as exc:
        return "__unreadable_" + type(exc).__name__ + "__"


def state():
    return {{
        "nonce": NONCE,
        "session": SESSION,
        "boot_id": read("/proc/sys/kernel/random/boot_id"),
        "counter": COUNTER["n"],
        "uptime_s": round(time.monotonic() - STARTED, 3),
        "proc_uptime_s": read("/proc/uptime").split(" ")[0],
        "shm": read(SHM_PATH),
        "pid": os.getpid(),
    }}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        raw = json.dumps(state()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


threading.Thread(target=tick, daemon=True).start()
HTTPServer(("0.0.0.0", {_AGENT_PORT}), Handler).serve_forever()
'''


# ===== in-band teardown ======================================================


def _teardown(ec2, st) -> None:
    """Ordered teardown with waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every step,
    then raises naming each one that failed on anything but an already-gone code."""
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    def _vpc_gone():
        still = ec2.describe_vpcs(VpcIds=[st["vpc"]])["Vpcs"]
        raise AssertionError(f"vpc {st['vpc']} is still describable: {still!r}")

    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _poll(
            lambda: _state(ec2, i), lambda s: s in ("terminated", "__gone__"),
            timeout_s=900.0, interval_s=2.0, what=f"instance {i} reaching 'terminated'"))
    if st.get("vpc"):
        _step("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=420.0, interval_s=2.0, what=f"every ENI in {st['vpc']!r} draining"))
    for assoc in st.get("assocs", []):
        _step(f"rtb-assoc {assoc}",
              lambda a=assoc: ec2.disassociate_route_table(AssociationId=a))
    for rtb in st.get("rtbs", []):
        _step(f"rtb {rtb}", lambda r=rtb: _retry_dependency(
            lambda: ec2.delete_route_table(RouteTableId=r)))
    for igw in st.get("igws", []):
        _step(f"igw-detach {igw}", lambda g=igw: _retry_dependency(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=g, VpcId=st["vpc"])))
        _step(f"igw {igw}", lambda g=igw: _retry_dependency(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=g)))
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
        _step("vpc-gone", _vpc_gone)
    left: list = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES:
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 - collected, then raised below
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


# ===== helpers (self-contained) =====================================


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _unless_gone(fn, code):
    """Run a backup cleanup that the ordered teardown may already have done: only *code* (the
    resource's own NotFound) counts as done; any other error still raises."""
    try:
        fn()
    except ClientError as exc:
        if _code(exc) != code:
            raise


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    """Bounded retry that RAISES on timeout — never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _stop_hibernate_when_ready(ec2, instance_id, *, timeout_s=900.0, interval_s=15.0):
    """Bounded retry around StopInstances(Hibernate=True) — RAISES on timeout, never returns a
    stale response. Not-ready is a transient EC2-side state, not a rejection of hibernation."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.stop_instances(InstanceIds=[instance_id], Hibernate=True)
        except ClientError as exc:
            transient = (
                _code(exc) == "UnsupportedOperation" and "not ready to hibernate" in str(exc)
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _retry_dependency(fn, timeout_s=240.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in ("DependencyViolation", "InvalidParameterDependency",
                                  "RequestLimitExceeded") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _describe(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _vpc_enis(ec2, vpc_id):
    return [
        eni["NetworkInterfaceId"]
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for eni in page["NetworkInterfaces"]
    ]


def _agent(ctx, ip, path):
    """The guest agent's JSON answer, or {} on any transport failure. A failure is an OBSERVATION so
    the enclosing bounded poll decides; the poll raises with a message."""
    try:
        sock = socket.create_connection(ctx.endpoint_host(ip, _AGENT_PORT), timeout=_CONNECT_TIMEOUT_S)
    except OSError:
        return {}
    try:
        sock.settimeout(_CONNECT_TIMEOUT_S)
        sock.sendall(
            f"GET {path} HTTP/1.0\r\nHost: sim2real\r\nConnection: close\r\n\r\n".encode()
        )
        chunks = []
        while True:
            block = sock.recv(65536)
            if not block:
                break
            chunks.append(block)
    except OSError:
        return {}
    finally:
        sock.close()
    raw = b"".join(chunks).decode("utf-8", "replace")
    head, _, body = raw.partition("\r\n\r\n")
    if "200" not in head.split("\r\n")[0]:
        return {}
    try:
        parsed = json.loads(body)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _zones_offering(ec2, instance_type):
    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    }
    assert usable, f"no available zone in this region offers {instance_type!r}"
    return usable


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
