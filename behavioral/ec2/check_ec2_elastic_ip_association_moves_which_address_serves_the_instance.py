"""ec2-elastic-ip-association-moves-which-address-serves-the-instance."""
from __future__ import annotations

import json
import socket
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-elastic-ip-association-moves-which-address-serves-the-instance"
GROUP = 'elastic-ip-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
LISTEN_PORT = 80
CONNECT_TIMEOUT_S = 2.0
# Marks failures of legs asserting a connection MUST complete, so a missing data plane reads as a
# failure rather than a connection error; legs asserting no connection never carry it.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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
    """(vpc_id, subnet_id) from the run's shared network in az, asserted to auto-assign a public
    IPv4 address on launch — the whole check is about which address answers, so both the original
    auto-assigned one and the one after the disassociation depend on that attribute."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        {"Name": "availability-zone", "Values": [az]},
    ])["Subnets"]
    if not subnets:
        raise AssertionError(f"account has no network subnet in {az}")
    subnet = subnets[0]
    assert subnet["MapPublicIpOnLaunch"] is True, (
        f"shared-network subnet {subnet['SubnetId']} does not auto-assign public IPv4 "
        f"(MapPublicIpOnLaunch={subnet['MapPublicIpOnLaunch']!r})"
    )
    return subnet["VpcId"], subnet["SubnetId"]


def _open_sg(ctx, vpc_id, port, scenario):
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real ec2 elastic-ip data-plane check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["GroupId"]

    def _drop():
        last = None
        for _ in range(120):
            try:
                ec2.delete_security_group(GroupId=gid)
                return
            except ClientError as exc:  # an ENI still references the group
                if _code(exc) == "InvalidGroup.NotFound":
                    return
                last = exc
                time.sleep(2)
        raise RuntimeError(f"security group {gid} was not deleted: {last!r}")

    ctx.on_cleanup(_drop)
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                        "IpRanges": [{"CidrIp": c, "Description": "sim2real ec2 eip check"}
                                     for c in ctx.ingress_cidrs()]}],
    )
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
    state = None
    while time.monotonic() < deadline:
        state = _instance_state(ctx, instance_id)
        if state in ("terminated", "__gone__"):
            return
        time.sleep(2)
    raise RuntimeError(f"instance {instance_id} was not terminated: still {state!r} after {timeout_s}s")


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

    Sliced at the marker because /dev/console is shared with the login getty, whose prompt can
    precede the guest's words on the same line.
    """
    for ln in reversed(text.splitlines()):
        if marker not in ln:
            continue
        parts = ln.strip().split()
        for i, p in enumerate(parts):
            if p == marker:
                return parts[i:]
    return None


def _http_get(ctx, host, port=LISTEN_PORT, timeout_s=CONNECT_TIMEOUT_S):
    """(body, None) on a completed HTTP exchange, or (None, 'ExcType: msg') on any transport
    failure. Which of the two happens IS the observation, so a failure is returned rather than
    raised."""
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


def _describe_address(ctx, allocation_id):
    """The one Address row for allocation_id, over every page of DescribeAddresses."""
    ec2 = ctx.client("ec2")
    found = [a for a in ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"]
             if a["AllocationId"] == allocation_id]
    assert len(found) == 1, (
        f"expected exactly one address row for {allocation_id}, got {found!r}"
    )
    return found[0]


def _listener_user_data(nonce):
    return (
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Associating an Elastic IP makes the instance answer on the EIP and stop answering on its previous
    auto-assigned public address; disassociating gives it a fresh auto-assigned address that answers.
    """
    ec2 = ctx.client("ec2")
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ec2-eip-moves-the-address"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx, az)
    sg_id = _open_sg(ctx, vpc_id, LISTEN_PORT, scenario)

    instance_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                               user_data=_listener_user_data(nonce),
                               SecurityGroupIds=[sg_id])["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                ctx=ctx, timeout_s=_budget_s(ctx, 600), interval_s=2,
                description=f"instance {instance_id} reaches 'running'")
    original_ip = _poll_until(
        lambda: _describe_instance_paginated(ctx, instance_id).get("PublicIpAddress"),
        lambda ip: bool(ip), ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2,
        description=f"instance {instance_id} gets an auto-assigned public IPv4 address")
    private_ip = _describe_instance_paginated(ctx, instance_id)["PrivateIpAddress"]

    text = _poll_until(lambda: _console(ctx, instance_id),
                       lambda t: "SIM2REAL-LISTENER-" in t, ctx=ctx, timeout_s=_budget_s(ctx, 900), interval_s=2,
                       description=f"the guest on {instance_id} reports its listener state")
    up = _console_fields(text, "SIM2REAL-LISTENER-UP")
    assert up is not None and len(up) >= 2 and up[1] == nonce, (
        f"the guest never confirmed its listener was serving the nonce {nonce!r}; it parsed as "
        f"{up!r} and the last 2KB of console was {text[-2048:]!r}"
    )

    # --- the control: the auto-assigned address really serves the nonce ---
    body, err = _poll_until(lambda: _http_get(ctx, original_ip), lambda r: r[0] is not None,
                            ctx=ctx, timeout_s=_budget_s(ctx, 180), interval_s=2,
                            description=(f"{DATAPLANE_MARKER}: the auto-assigned address "
                                         f"{original_ip} serves the nonce"))
    assert nonce in body, (
        f"{DATAPLANE_MARKER}: the auto-assigned address {original_ip} answered but not with the "
        f"guest's nonce {nonce!r}: {body!r}"
    )

    # --- associate an Elastic IP. Cleanup order matters: release AFTER disassociate, and
    #     ctx.on_cleanup is LIFO, so the disassociate registered later runs first. ---
    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )
    allocation_id, eip = alloc["AllocationId"], alloc["PublicIp"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))
    assoc_id = ec2.associate_address(AllocationId=allocation_id,
                                    InstanceId=instance_id)["AssociationId"]

    def _disassociate():
        try:
            ec2.disassociate_address(AssociationId=assoc_id)
        except ClientError as exc:
            if _code(exc) not in ("InvalidAssociationID.NotFound", "InvalidAssociationIDNotFound"):
                raise

    ctx.on_cleanup(_disassociate)
    assert eip != original_ip, (
        f"the allocated Elastic IP {eip!r} is the instance's existing auto-assigned address "
        f"{original_ip!r}, so the check could not tell the two apart"
    )

    _poll_until(lambda: _describe_instance_paginated(ctx, instance_id).get("PublicIpAddress"),
                lambda ip: ip == eip, ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2,
                description=f"DescribeInstances reports {instance_id}'s public address as the EIP "
                            f"{eip}")

    # --- the EIP serves the SAME listener: same nonce, new address ---
    body, err = _poll_until(lambda: _http_get(ctx, eip), lambda r: r[0] is not None,
                            ctx=ctx, timeout_s=_budget_s(ctx, 180), interval_s=2,
                            description=f"{DATAPLANE_MARKER}: the Elastic IP {eip} serves the nonce")
    assert nonce in body, (
        f"{DATAPLANE_MARKER}: the Elastic IP {eip} answered but not with the guest's nonce "
        f"{nonce!r}: {body!r} — the address moved to a different listener"
    )

    # --- effect absent: the OLD address no longer serves it ---
    # It stops answering within seconds, but that latency is undocumented, so absence is polled.
    body, err = _poll_until(lambda: _http_get(ctx, original_ip), lambda r: r[0] is None,
                            ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2,
                            description=(f"the old auto-assigned address {original_ip} stops "
                                         f"serving the nonce once the EIP {eip} is associated"))
    assert body is None and err is not None, (
        f"after the association the old address {original_ip} must stop answering; it returned "
        f"body={body!r} err={err!r}"
    )

    addr = _describe_address(ctx, allocation_id)
    assert addr["InstanceId"] == instance_id, (
        f"DescribeAddresses reports InstanceId {addr.get('InstanceId')!r} for {eip}, expected "
        f"{instance_id!r}"
    )
    assert addr["PrivateIpAddress"] == private_ip, (
        f"DescribeAddresses reports PrivateIpAddress {addr.get('PrivateIpAddress')!r} for {eip}, "
        f"expected the instance's {private_ip!r}"
    )

    # --- disassociate, and a NEW auto-assigned address serves the nonce again ---
    ec2.disassociate_address(AssociationId=assoc_id)
    new_ip = _poll_until(
        lambda: _describe_instance_paginated(ctx, instance_id).get("PublicIpAddress"),
        lambda ip: bool(ip) and ip != eip, ctx=ctx, timeout_s=_budget_s(ctx, 600), interval_s=2,
        description=(f"instance {instance_id} is auto-assigned a fresh public address after the "
                     f"EIP {eip} is disassociated"))
    body, err = _poll_until(lambda: _http_get(ctx, new_ip), lambda r: r[0] is not None,
                            ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2,
                            description=(f"{DATAPLANE_MARKER}: the fresh auto-assigned address "
                                         f"{new_ip} serves the nonce"))
    assert nonce in body, (
        f"{DATAPLANE_MARKER}: the fresh address {new_ip} answered but not with the guest's nonce "
        f"{nonce!r}: {body!r} (the addresses this run used were original={original_ip!r} "
        f"eip={eip!r} new={new_ip!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
