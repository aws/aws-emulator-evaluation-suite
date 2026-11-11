"""ec2-instance-user-data-executes-and-the-guest-reports-the-nonce."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-instance-user-data-executes-and-the-guest-reports-the-nonce"
GROUP = 'instance-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'

# ===== helpers =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result.

    Raises AssertionError on timeout: a machine that launched but never spoke is a FAIL, not an
    environment limitation.
    """
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
    """An AMI id from an AWS-published SSM public parameter — never a hardcoded, region-bound id."""
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _usable_azs(ctx, instance_type=INSTANCE_TYPE):
    """AZ names that are BOTH 'available' and offer instance_type.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state, and
    describe_availability_zones says nothing about instance types.
    """
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


def _default_subnet(ctx, az):
    """The network subnet in az. Raises AssertionError only if the account has no shared network at all,
    which is a property of the account rather than of EC2's behaviour."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        {"Name": "availability-zone", "Values": [az]},
    ])["Subnets"]
    if not subnets:
        raise AssertionError(f"account has no network subnet in {az}")
    return subnets[0]["SubnetId"]


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type=INSTANCE_TYPE, **kw):
    """RunInstances with the instance AND its root volume tagged at launch, so an interrupted
    teardown leaves attributable resources for cleanup."""
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}]
    resp = ec2.run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_kv},
            {"ResourceType": "volume", "Tags": tags_kv},
        ],
        **kw,
    )
    return resp["Instances"][0]


def _terminate_and_wait(ctx, instance_id, timeout_s=600):
    """Terminate and WAIT for 'terminated', so the ENI and the root volume go with it before any
    VPC/subnet teardown registered earlier runs."""
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


def _describe_instance_paginated(ctx, instance_id):
    """The instance, found by walking every page of DescribeInstances filtered on its id.

    Paginated deliberately: other instances in the account can push a reservation off page one.
    """
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id} not found in any page of DescribeInstances")


def _console(ctx, instance_id):
    """(text, response) for GetConsoleOutput(Latest=True).

    Latest=True is required on Nitro instance types. Output is used AS RETURNED: botocore's
    ``decode_console_output`` handler already base64-decodes it in place (and leaves it untouched
    when it is not valid base64), so decoding again here turns the guest's own words into binary
    noise.
    """
    resp = ctx.client("ec2").get_console_output(InstanceId=instance_id, Latest=True)
    return resp.get("Output") or "", resp


def _console_fields(text, marker):
    """The whitespace fields of the last console line containing marker, starting AT the marker.

    Sliced at the marker rather than split over the whole line, because /dev/console is shared with
    the login getty. On real AWS a guest report arrives as ``'ip-172-31-36-148 login: SIM2REAL-DISK
    nvme1n1 1073741824'``, so any parser that indexes from either end of the line reads the getty's
    words instead of the guest's.
    """
    for ln in reversed(text.splitlines()):
        if marker not in ln:
            continue
        parts = ln.strip().split()
        for i, p in enumerate(parts):
            if p == marker:
                return parts[i:]
    return None


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A launched instance executes its user data and reports a per-run nonce plus the instance id it read
    from IMDSv2 on the serial console; that id must equal the one RunInstances returned."""
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ec2-user-data-executes"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    subnet_id = _default_subnet(ctx, az)

    # The guest writes to /dev/console directly: cloud-init's own stdout is teed to
    # /var/log/cloud-init-output.log, which GetConsoleOutput never sees.
    user_data = (
        "#!/bin/bash\n"
        f'echo "SIM2REAL-NONCE {nonce}" > /dev/console\n'
        "TOK=$(curl -s -m 10 -X PUT http://169.254.169.254/latest/api/token"
        " -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')\n"
        "IID=$(curl -s -m 10 -H \"X-aws-ec2-metadata-token: $TOK\""
        " http://169.254.169.254/latest/meta-data/instance-id)\n"
        'echo "SIM2REAL-IID $IID" > /dev/console\n'
        f'echo "SIM2REAL-DONE {nonce}" > /dev/console\n'
    )

    inst = _run_instance(ctx, ami=ami, subnet_id=subnet_id, user_data=user_data, scenario=scenario)
    instance_id = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))

    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=600, interval_s=5,
                description=f"instance {instance_id} reaches 'running'")

    # --- the machine speaks: a per-run nonce written by the check's own script ---
    text, resp = _poll_until(lambda: _console(ctx, instance_id),
                             lambda tr: f"SIM2REAL-DONE {nonce}" in tr[0],
                             timeout_s=900, interval_s=15,
                             description=(f"console output of {instance_id} carries "
                                          f"'SIM2REAL-DONE {nonce}'"))
    assert nonce in text, (
        f"the guest never echoed the per-run nonce {nonce!r}; last 2KB of console output was "
        f"{text[-2048:]!r}"
    )

    # --- the identity law: the guest's own view of who it is matches the control plane's ---
    iid_fields = _console_fields(text, "SIM2REAL-IID")
    assert iid_fields is not None and len(iid_fields) >= 2, (
        f"the guest never reported its IMDSv2 instance id; it parsed as {iid_fields!r} out of a "
        f"console whose last 2KB was {text[-2048:]!r}"
    )
    guest_iid = iid_fields[1]
    assert guest_iid == instance_id, (
        f"the guest read its own instance id as {guest_iid!r} from IMDSv2 but RunInstances "
        f"returned {instance_id!r} — the control plane and the running machine disagree about "
        f"which machine this is"
    )

    # --- the console response is bound to this instance and to a post after the launch ---
    assert resp["InstanceId"] == instance_id, (
        f"GetConsoleOutput echoed InstanceId {resp.get('InstanceId')!r}, expected {instance_id!r}"
    )
    described = _describe_instance_paginated(ctx, instance_id)
    launch_time = described["LaunchTime"]
    assert resp["Timestamp"] >= launch_time, (
        f"GetConsoleOutput Timestamp {resp['Timestamp']!r} predates the instance's own LaunchTime "
        f"{launch_time!r} — the output cannot have come from this boot"
    )
    assert described["State"]["Name"] == "running", (
        f"the instance that just spoke reports state {described['State']['Name']!r}, expected "
        f"'running'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
