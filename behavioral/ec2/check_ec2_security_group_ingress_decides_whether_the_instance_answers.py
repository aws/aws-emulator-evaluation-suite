"""ec2-security-group-ingress-decides-whether-the-instance-answers."""
from __future__ import annotations

import json
import socket
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-security-group-ingress-decides-whether-the-instance-answers"
GROUP = 'security-group-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
LISTEN_PORT = 80
CONNECT_TIMEOUT_S = 8.0
# Marks the failure of a leg that asserts the connection MUST complete, so a target with no data
# plane at all reads as a failure rather than a connection error. The legs asserting a connection
# must NOT complete are trivially satisfied by a target with no listener, so they never carry it.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


# ===== helpers (self-contained) =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last observation: {last!r}"
    )


def _ssm_ami(ctx, parameter=AL2023_SSM):
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _usable_azs(ctx, instance_type=INSTANCE_TYPE):
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable


def _default_vpc_and_subnet(ctx, az):
    """(vpc_id, subnet_id) from the run's shared network in az.

    The shared network is used deliberately rather than built: its subnets already carry an
    internet-gateway route and MapPublicIpOnLaunch, so this check leaks no IGW, route table or
    VPC even if teardown is interrupted, and the ONE variable it manipulates is the security
    group rule.
    """
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        {"Name": "availability-zone", "Values": [az]},
    ])["Subnets"]
    if not subnets:
        raise AssertionError(f"account has no network subnet in {az}")
    return subnets[0]["VpcId"], subnets[0]["SubnetId"]


def _closed_sg(ctx, vpc_id, scenario):
    """A security group with NO ingress rules at all, tagged at creation. Deleted on a bounded
    retry loop because an instance ENI keeps the group referenced for a while after termination."""
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real ec2 security-group data-plane enforcement check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["GroupId"]

    def _drop():
        # The instance ENI still detaching refuses the delete with DependencyViolation.
        deadline = time.monotonic() + 240
        while True:
            try:
                ec2.delete_security_group(GroupId=gid)
                return
            except ClientError as exc:
                code = _code(exc)
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop)
    return gid


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type=INSTANCE_TYPE, **kw):
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}]
    return ec2.run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_kv},
            {"ResourceType": "volume", "Tags": tags_kv},
        ],
        **kw,
    )["Instances"][0]


def _instance_state(ctx, instance_id):
    ec2 = ctx.client("ec2")
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ctx, instance_id, timeout_s=600):
    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ctx, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _describe_instance_paginated(ctx, instance_id):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id} not found in any page of DescribeInstances")


def _console(ctx, instance_id):
    """The instance's serial console text, AS RETURNED by GetConsoleOutput(Latest=True).

    Latest=True is required on Nitro instance types. Output is not decoded here: botocore's
    ``decode_console_output`` handler already base64-decodes it in place (and leaves it untouched
    when it is not valid base64), so decoding again turns the guest's own words into binary noise.
    """
    resp = ctx.client("ec2").get_console_output(InstanceId=instance_id, Latest=True)
    return resp.get("Output") or ""


def _console_fields(text, marker):
    """The whitespace fields of the last console line containing marker, starting AT the marker.

    Sliced at the marker rather than split over the whole line, because /dev/console is shared with
    the login getty. On AWS a guest report arrives as
    ``'ip-172-31-36-148 login: SIM2REAL-DISK nvme1n1 1073741824'``, so any parser that indexes from
    either end of the line reads the getty's words instead of the guest's.
    """
    for ln in reversed(text.splitlines()):
        if marker not in ln:
            continue
        parts = ln.strip().split()
        for i, p in enumerate(parts):
            if p == marker:
                return parts[i:]
    return None


def _http_get(ctx, host, port, timeout_s=CONNECT_TIMEOUT_S):
    """(body, None) on a completed HTTP exchange, or (None, 'ExcType: msg') on any transport
    failure. A refusal or a timeout is an OBSERVATION here, not an exception, because the whole
    point of the check is which of the two happens."""
    try:
        sock = socket.create_connection(ctx.endpoint_host(host, port), timeout=timeout_s)
    except OSError as exc:  # refused, reset, unreachable or timed out: the observation
        return None, f"{type(exc).__name__}: {exc}"
    try:
        sock.settimeout(timeout_s)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: sim2real\r\n\r\n")
        chunks = []
        while True:
            b = sock.recv(4096)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks).decode("utf-8", "replace"), None
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()


def _ingress_rules(ctx, group_id):
    """Every IpPermissions entry on group_id, read back from DescribeSecurityGroups."""
    ec2 = ctx.client("ec2")
    groups = []
    for page in ec2.get_paginator("describe_security_groups").paginate(GroupIds=[group_id]):
        groups += page["SecurityGroups"]
    assert len(groups) == 1, f"expected exactly one security group {group_id}, got {groups!r}"
    return groups[0]["IpPermissions"]


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A security group rule is enforced on real packets: with no matching ingress rule a TCP
    connection to the instance's listener does not complete, after authorizing it does and serves the
    guest's nonce, and after revoking it stops completing again."""
    ec2 = ctx.client("ec2")
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ec2-sg-ingress-enforced"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx, az)
    sg_id = _closed_sg(ctx, vpc_id, scenario)
    assert _ingress_rules(ctx, sg_id) == [], (
        f"a freshly created security group must have no ingress rules, got "
        f"{_ingress_rules(ctx, sg_id)!r}"
    )

    user_data = (
        "#!/bin/bash\n"
        "mkdir -p /var/www\n"
        f'printf "%s\\n" "{nonce}" > /var/www/index.html\n'
        f"nohup python3 -m http.server {LISTEN_PORT} --directory /var/www"
        " > /var/log/sim2real-httpd.log 2>&1 &\n"
        "for i in $(seq 1 60); do\n"
        f"  if curl -s -m 3 http://127.0.0.1:{LISTEN_PORT}/ | grep -q {nonce}; then\n"
        f'    echo "SIM2REAL-LISTENER-UP {nonce}" > /dev/console\n'
        "    exit 0\n"
        "  fi\n"
        "  sleep 2\n"
        "done\n"
        'echo "SIM2REAL-LISTENER-FAILED" > /dev/console\n'
    )

    inst = _run_instance(ctx, ami=ami, subnet_id=subnet_id, user_data=user_data,
                         scenario=scenario, SecurityGroupIds=[sg_id])
    instance_id = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))

    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=600, interval_s=5,
                description=f"instance {instance_id} reaches 'running'")
    public_ip = _poll_until(
        lambda: _describe_instance_paginated(ctx, instance_id).get("PublicIpAddress"),
        lambda ip: bool(ip), timeout_s=300, interval_s=5,
        description=f"instance {instance_id} gets an auto-assigned public IPv4 address")

    # --- the positive control: the guest itself says the listener is serving the nonce ---
    text = _poll_until(lambda: _console(ctx, instance_id),
                       lambda t: "SIM2REAL-LISTENER-" in t, timeout_s=900, interval_s=15,
                       description=f"the guest on {instance_id} reports its listener state")
    up = _console_fields(text, "SIM2REAL-LISTENER-UP")
    assert up is not None and len(up) >= 2 and up[1] == nonce, (
        f"the guest never confirmed its own listener was serving the nonce {nonce!r}; it parsed as "
        f"{up!r} and the last 2KB of console was {text[-2048:]!r}"
    )

    # --- leg 1: no ingress rule, so the packet must not reach the listener ---
    body, err = _http_get(ctx, public_ip, LISTEN_PORT)
    assert body is None, (
        f"with NO ingress rule the security group must drop the connection, but "
        f"{public_ip}:{LISTEN_PORT} answered {body!r}"
    )
    closed_err = err

    # --- leg 2: authorize, and the SAME listener becomes reachable ---
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": LISTEN_PORT, "ToPort": LISTEN_PORT,
                        "IpRanges": [{"CidrIp": c, "Description": "sim2real ec2 sg enforcement check"}
                                     for c in ctx.ingress_cidrs()]}],
    )
    body, err = _poll_until(lambda: _http_get(ctx, public_ip, LISTEN_PORT),
                            lambda r: r[0] is not None, timeout_s=180, interval_s=5,
                            description=(f"{DATAPLANE_MARKER}: {public_ip}:{LISTEN_PORT} becomes "
                                         f"reachable after the ingress authorization (it was "
                                         f"{closed_err!r} before)"))
    assert nonce in body, (
        f"{DATAPLANE_MARKER}: the authorized connection completed but the body did not carry the "
        f"guest's nonce {nonce!r}; got {body!r} — the reachable listener is not the one this check "
        f"started"
    )
    rules = _ingress_rules(ctx, sg_id)
    assert len(rules) == 1, (
        f"expected exactly one IpPermissions entry while the rule exists, got {rules!r}"
    )
    assert rules[0]["FromPort"] == LISTEN_PORT and rules[0]["ToPort"] == LISTEN_PORT, (
        f"the authorized rule does not describe port {LISTEN_PORT}: {rules[0]!r}"
    )

    # --- leg 3: revoke, and the same listener stops answering new connections ---
    ec2.revoke_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": LISTEN_PORT, "ToPort": LISTEN_PORT,
                        "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}],
    )
    body, err = _poll_until(lambda: _http_get(ctx, public_ip, LISTEN_PORT),
                            lambda r: r[0] is None, timeout_s=180, interval_s=5,
                            description=(f"{public_ip}:{LISTEN_PORT} stops completing after the "
                                         f"ingress revoke (it served {nonce!r} before)"))
    assert body is None, (
        f"after the revoke the security group must drop the connection again, but the listener "
        f"answered {body!r}"
    )
    assert err is not None, (
        f"a dropped connection must surface as a transport failure, got err={err!r}"
    )
    assert _ingress_rules(ctx, sg_id) == [], (
        f"after the revoke the group must carry zero ingress rules, got "
        f"{_ingress_rules(ctx, sg_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
