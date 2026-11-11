"""guest-user-data-output-read-back-through-run-command."""
from __future__ import annotations

import base64
import hashlib
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guest-user-data-output-read-back-through-run-command"
GROUP = 'guest-execution'
SERVICES = ['ec2', 'ssm']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_GUEST_DIR = "/var/lib/sim2real-guest"



def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=_THROTTLE, retries=40, delay=5.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Poll probe() until predicate(result); AssertionError on timeout.

    A machine that launched and never converged is a FAIL, never an environment limitation.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _delete_with_retry(fn, *, gone=(), busy=("DependencyViolation", "InvalidParameterDependency"),
                       attempts=40, delay=5.0):
    """Delete, tolerating 'already gone' and retrying 'still referenced'.

    Callers remove the referent first; this only absorbs the lag until EC2 admits it is gone.
    """
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = _code(exc)
            if code in gone:
                return None
            if code in busy and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that is BOTH 'available' and offers instance_type.

    Instance type offerings omit zone state, and AZ names are per-account aliases.
    """
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _network(ctx, scenario):
    """A dedicated VPC with one public subnet and an egress-only security group.

    Built rather than borrowed: an account may have no default VPC. Every resource is tagged in
    the same call that creates it.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.171.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tag}],
    )["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _delete_with_retry(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
            gone=("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound",
                  "InvalidVpcID.NotFound"))
        _delete_with_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
                           gone=("InvalidInternetGatewayID.NotFound",))

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    # The VPC's own main route table, which is created with the VPC and destroyed with it.
    rtb_id = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0"),
        gone=("InvalidRoute.NotFound", "InvalidRouteTableID.NotFound")))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.171.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-guest-"), VpcId=vpc_id,
        Description="sim2real guest-execution egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return vpc_id, subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-guest-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real guest-execution managed instance role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_role():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
        except ClientError as exc:
            if _code(exc) != "NoSuchEntity":
                raise
        _delete_with_retry(lambda: iam.delete_role(RoleName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)

    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_profile():
        _delete_with_retry(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=name, RoleName=name), gone=("NoSuchEntity",),
            busy=("DeleteConflict",))
        _delete_with_retry(lambda: iam.delete_instance_profile(InstanceProfileName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


def _instance_state(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated' — not merely 'shutting-down'.

    The ENI and the root volume only go away at 'terminated', and the subnet, security group and
    VPC deletions registered EARLIER (and therefore running later, LIFO) all depend on that.
    """
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _launch(ctx, *, profile_name, subnet_id, sg_id, user_data, scenario, metadata_options=None):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    tag = [{"Key": "sim2real", "Value": scenario}]
    kw = {}
    if metadata_options is not None:
        kw["MetadataOptions"] = metadata_options
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            UserData=user_data,
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
            **kw,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=40, delay=5.0)
    return resv["Instances"][0]


def _wait_online(ctx, instance_id, timeout_s=600):
    """Wait for the SSM agent on this host to report Online. Never registering is a FAIL."""
    ssm = ctx.client("ssm")

    def _view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    return _poll(_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=timeout_s, interval_s=10.0,
                 what=f"the SSM agent on {instance_id} coming Online")


def _run_shell(ctx, instance_id, commands, *, what, timeout_s=300):
    """Send commands to the guest and return the terminal invocation record."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=300,
        Comment="sim2real guest-execution read-back"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=5.0,
                 what=f"{what}: invocation {command_id} reaching a terminal status")


def _marker(stdout, marker):
    """The text after `marker` on the LAST line that starts with it, or None.

    Anchored at the marker rather than split over the whole line so an extra word from the guest's
    own tooling cannot be read as the value.
    """
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value




@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """User data handed to RunInstances executes on the guest, and Run Command reads back what it
    produced: a per-run digest, sum(1..100), the IMDSv2 instance id, and the user-data bytes' sha256.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html
    """
    scenario = "guest-user-data-read-back"
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    expected_digest = hashlib.sha256(nonce.encode()).hexdigest()

    ec2 = ctx.client("ec2")
    _vpc_id, subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)

    user_data = (
        "#!/bin/bash\n"
        f"mkdir -p {_GUEST_DIR}\n"
        f"printf '%s' '{nonce}' | sha256sum | cut -d' ' -f1 > {_GUEST_DIR}/digest\n"
        f"seq 1 100 | awk '{{s+=$1}} END {{print s}}' > {_GUEST_DIR}/sum\n"
        "TOK=$(curl -s -m 10 -X PUT http://169.254.169.254/latest/api/token"
        " -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')\n"
        "curl -s -m 10 -H \"X-aws-ec2-metadata-token: $TOK\""
        f" http://169.254.169.254/latest/meta-data/instance-id > {_GUEST_DIR}/iid\n"
        "sha256sum < /var/lib/cloud/instance/user-data.txt | cut -d' ' -f1"
        f" > {_GUEST_DIR}/userdata-digest\n"
        f"echo ok > {_GUEST_DIR}/done\n"
    )
    expected_user_data_digest = hashlib.sha256(user_data.encode()).hexdigest()

    inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                   user_data=user_data, scenario=scenario)
    instance_id = inst["InstanceId"]
    # Registered before the first wait: a host that never comes up must not strand a billing
    # instance.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    info = _wait_online(ctx, instance_id)
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )

    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="userData")
    served = base64.b64decode(attr["UserData"]["Value"]).decode()
    assert served == user_data, (
        "DescribeInstanceAttribute must return exactly the user data RunInstances was given; got "
        f"{served!r}"
    )

    inv = _run_shell(ctx, instance_id, [
        "set -uo pipefail",
        # Wait for the sentinel the user-data script writes last: cloud-init and the SSM agent
        # start concurrently, so the command can legitimately arrive first. A guest that never
        # finishes falls through to the `cat` below and FAILS naming the missing file.
        f"for _ in $(seq 1 60); do [ -f {_GUEST_DIR}/done ] && break; sleep 2; done",
        "set -e",
        f'echo "GUEST-DONE $(cat {_GUEST_DIR}/done)"',
        f'echo "GUEST-DIGEST $(cat {_GUEST_DIR}/digest)"',
        f'echo "GUEST-SUM $(cat {_GUEST_DIR}/sum)"',
        f'echo "GUEST-IID $(cat {_GUEST_DIR}/iid)"',
        f'echo "GUEST-UD-DIGEST $(cat {_GUEST_DIR}/userdata-digest)"',
        'echo "GUEST-CLOUDINIT $(cloud-init status | tr -d \'\\n\')"',
    ], what="reading back the user-data artefacts")

    assert inv["Status"] == "Success", (
        f"the read-back invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stdout={inv.get('StandardOutputContent')!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"ResponseCode was {inv['ResponseCode']!r}, stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["StandardErrorContent"] == "", (
        f"the read-back script wrote to stderr: {inv['StandardErrorContent']!r}"
    )
    out = inv["StandardOutputContent"]

    assert _marker(out, "GUEST-DONE") == "ok", (
        f"the guest never wrote its completion sentinel; stdout was {out!r}"
    )
    assert _marker(out, "GUEST-DIGEST") == expected_digest, (
        f"the guest must have hashed the per-run nonce {nonce!r} to {expected_digest!r}; it "
        f"reported {_marker(out, 'GUEST-DIGEST')!r} — the user data did not execute as given"
    )
    assert _marker(out, "GUEST-SUM") == "5050", (
        f"the guest's arithmetic over 1..100 reported {_marker(out, 'GUEST-SUM')!r}, expected "
        f"'5050'"
    )
    guest_iid = _marker(out, "GUEST-IID")
    assert guest_iid == instance_id, (
        f"the guest read its own instance id as {guest_iid!r} from IMDSv2 but RunInstances "
        f"returned {instance_id!r} — the control plane and the running machine disagree about "
        f"which machine this is"
    )
    assert _marker(out, "GUEST-UD-DIGEST") == expected_user_data_digest, (
        f"the bytes cloud-init found in /var/lib/cloud/instance/user-data.txt hashed to "
        f"{_marker(out, 'GUEST-UD-DIGEST')!r}, but the bytes handed to RunInstances hash to "
        f"{expected_user_data_digest!r} — the guest did not receive what the control plane was given"
    )
    cloudinit = _marker(out, "GUEST-CLOUDINIT")
    assert cloudinit is not None and "status: done" in cloudinit, (
        f"cloud-init must report a completed run on the machine that produced those artefacts, got "
        f"{cloudinit!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
