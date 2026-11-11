"""ec2-launch-with-a-private-ip-already-in-use-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-launch-with-a-private-ip-already-in-use-rejected"
GROUP = 'errors'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
ERR_IP_IN_USE = 'InvalidIPAddress.InUse'
VPC_CIDR = '10.77.0.0/16'
SUBNET_CIDR = '10.77.1.0/24'
#: AWS reserves the FIRST FOUR and the LAST address of every subnet CIDR. Both of these sit in the
#: middle of the /24, so the refusal cannot be the reserved-address error wearing another name.
ADDR_TAKEN = '10.77.1.100'
ADDR_FREE = '10.77.1.150'

# ===== helpers (self-contained) =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


class _UnexpectedSuccess(Exception):
    """Raised when a call the check expects to be refused succeeds."""


def _error_of(fn):
    """(code, message) for a call that MUST fail. Raises _UnexpectedSuccess if it does not."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise _UnexpectedSuccess(f"the call succeeded and returned {resp!r}")


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
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable


def _own_vpc(ctx, az, scenario, run_id):
    """(vpc_id, subnet_id) for a VPC the check builds itself, so it knows which addresses are free.

    A shared subnet's addresses may be held by another instance, breaking 'exactly one ENI holds X'.
    """
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}, {"Key": "sim2real-run", "Value": run_id}]
    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tags_kv}],
    )["Vpc"]["VpcId"]

    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                             "InvalidVpcID.NotFound"))
    _poll_until(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
                lambda s: s == "available", timeout_s=180, interval_s=3,
                description=f"vpc {vpc_id} reaches 'available'")

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags_kv}],
    )["Subnet"]["SubnetId"]

    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                             "InvalidSubnetID.NotFound"))
    _poll_until(lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["State"],
                lambda s: s == "available", timeout_s=180, interval_s=3,
                description=f"subnet {subnet_id} reaches 'available'")
    return vpc_id, subnet_id


def _delete_when_free(fn, gone_code, timeout_s=300):
    """Teardown delete: retry DependencyViolation (an instance's ENI still releasing) every 2 s to
    the deadline, return on the resource's own not-found code, raise everything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) == gone_code:
                return
            if _code(exc) != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, run_id, private_ip,
                  instance_type=INSTANCE_TYPE):
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}, {"Key": "sim2real-run", "Value": run_id}]
    return ec2.run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        PrivateIpAddress=private_ip, UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_kv},
            {"ResourceType": "volume", "Tags": tags_kv},
        ],
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
    """Terminate and wait for 'terminated': the ENI must be released before subnet/VPC teardown."""
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


def _instances_tagged(ctx, run_id):
    """Every non-terminated instance carrying this run's tag, over every page of DescribeInstances."""
    ec2 = ctx.client("ec2")
    found = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:sim2real-run", "Values": [run_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["State"]["Name"] not in ("terminated", "shutting-down"):
                    found.append((inst["InstanceId"], inst["State"]["Name"],
                                  inst.get("PrivateIpAddress")))
    return sorted(found)


def _enis_holding(ctx, subnet_id, address):
    """Every ENI in subnet_id whose primary or secondary private address is `address`, over every
    page of DescribeNetworkInterfaces."""
    ec2 = ctx.client("ec2")
    out = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]):
        for eni in page["NetworkInterfaces"]:
            addrs = {a["PrivateIpAddress"] for a in eni.get("PrivateIpAddresses", [])}
            addrs.add(eni.get("PrivateIpAddress"))
            if address in addrs:
                out.append((eni["NetworkInterfaceId"],
                            (eni.get("Attachment") or {}).get("InstanceId")))
    return sorted(out)


def _console(ctx, instance_id):
    """The instance's serial console text from GetConsoleOutput(Latest=True), required on Nitro.

    Not decoded here: botocore's ``decode_console_output`` handler already base64-decodes it.
    """
    resp = ctx.client("ec2").get_console_output(InstanceId=instance_id, Latest=True)
    return resp.get("Output") or ""


def _console_fields(text, marker):
    """The whitespace fields of the last console line containing marker, starting at the marker.

    /dev/console is shared with the login getty, whose prompt can prefix the guest's line.
    """
    for ln in reversed(text.splitlines()):
        if marker not in ln:
            continue
        parts = ln.strip().split()
        for i, p in enumerate(parts):
            if p == marker:
                return parts[i:]
    return None


def _guest_script():
    """User data that echoes the instance's own private address read from IMDSv2.

    This shows the address is bound to a live interface, not merely a control-plane field.
    """
    return (
        "#!/bin/bash\n"
        "TOK=$(curl -s -m 10 -X PUT http://169.254.169.254/latest/api/token"
        " -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')\n"
        "IP=$(curl -s -m 10 -H \"X-aws-ec2-metadata-token: $TOK\""
        " http://169.254.169.254/latest/meta-data/local-ipv4)\n"
        'echo "SIM2REAL-LOCALIP $IP" > /dev/console\n'
    )


# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RunInstances with a PrivateIpAddress held by a live instance in the same subnet fails with
    InvalidIPAddress.InUse; no second instance or ENI appears, and a free address launches fine.
    """
    ec2 = ctx.client("ec2")
    scenario = "ec2-private-ip-in-use"
    run_id = "sim2real-run-" + uuid.uuid4().hex[:12]

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    _, subnet_id = _own_vpc(ctx, az, scenario, run_id)

    # --- full setup: instance A really holds ADDR_TAKEN ---
    a_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario, run_id=run_id,
                         private_ip=ADDR_TAKEN, user_data=_guest_script())["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, a_id))
    _poll_until(lambda: _instance_state(ctx, a_id), lambda s: s == "running",
                timeout_s=600, interval_s=5,
                description=f"instance A {a_id} reaches 'running' on {ADDR_TAKEN}")
    a = _describe_instance_paginated(ctx, a_id)
    assert a["PrivateIpAddress"] == ADDR_TAKEN, (
        f"instance A was launched with PrivateIpAddress={ADDR_TAKEN!r} but DescribeInstances "
        f"reports {a['PrivateIpAddress']!r}"
    )
    a_text = _poll_until(lambda: _console(ctx, a_id),
                         lambda t: "SIM2REAL-LOCALIP" in t, timeout_s=900, interval_s=15,
                         description=f"instance A {a_id} reports its own IMDSv2 local-ipv4")
    guest = _console_fields(a_text, "SIM2REAL-LOCALIP")
    assert guest is not None and len(guest) >= 2 and guest[1] == ADDR_TAKEN, (
        f"the guest reported its own IMDSv2 local-ipv4 as {guest!r}, not {ADDR_TAKEN!r}, so that "
        f"address is not demonstrably bound to a live interface and the refusal below would prove "
        f"nothing"
    )

    # --- break exactly one thing: reuse the address that is now demonstrably taken ---
    code, message = _error_of(
        lambda: _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario, run_id=run_id,
                              private_ip=ADDR_TAKEN, user_data=_guest_script())
    )
    assert code == ERR_IP_IN_USE, (
        f"launching a second instance on {ADDR_TAKEN!r}, held by {a_id}, must be refused with "
        f"{ERR_IP_IN_USE!r}, got {code!r}: {message!r}"
    )
    assert message == f"Address {ADDR_TAKEN} is in use.", message

    # --- effect absent, twice over ---
    tagged = _instances_tagged(ctx, run_id)
    assert len(tagged) == 1, (
        f"exactly ONE non-terminated instance may carry run tag {run_id!r} after the refusal; "
        f"DescribeInstances (paginated) returned {tagged!r}"
    )
    holders = _enis_holding(ctx, subnet_id, ADDR_TAKEN)
    assert holders == [(a["NetworkInterfaces"][0]["NetworkInterfaceId"], a_id)], (
        f"exactly ONE ENI in {subnet_id} may hold {ADDR_TAKEN!r} and it must belong to {a_id!r}; "
        f"DescribeNetworkInterfaces (paginated) returned {holders!r}"
    )

    # --- positive control: the identical launch with a free address from the same CIDR ---
    b_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario, run_id=run_id,
                         private_ip=ADDR_FREE, user_data=_guest_script())["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, b_id))
    _poll_until(lambda: _instance_state(ctx, b_id), lambda s: s == "running",
                timeout_s=600, interval_s=5,
                description=f"control instance {b_id} reaches 'running' on {ADDR_FREE}")
    b = _describe_instance_paginated(ctx, b_id)
    assert b["PrivateIpAddress"] == ADDR_FREE, (
        f"the control instance must hold exactly {ADDR_FREE!r}, DescribeInstances reports "
        f"{b['PrivateIpAddress']!r}"
    )
    assert len(_instances_tagged(ctx, run_id)) == 2, (
        f"after the control launch exactly two instances may carry run tag {run_id!r}, got "
        f"{_instances_tagged(ctx, run_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
