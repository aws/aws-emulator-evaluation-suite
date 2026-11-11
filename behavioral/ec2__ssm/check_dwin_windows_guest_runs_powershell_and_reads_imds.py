"""dwin-windows-guest-runs-powershell-and-reads-imds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dwin-windows-guest-runs-powershell-and-reads-imds"
GROUP = 'windows-guest'
SERVICES = ['ec2', 'ssm']

_WINDOWS_AMI_PARAM = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.large"
_SEED = 41
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A Windows guest runs a PowerShell script via Run Command and the identity it reads from IMDSv2 and
    its computer name match EC2 and SSM; AWS-RunShellScript is refused UnsupportedPlatformType and leaves
    no invocation."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    # --- everything decidable, before the first create ------------------------
    az = _usable_az(ec2, _INSTANCE_TYPE)
    ami = ssm.get_parameter(Name=_WINDOWS_AMI_PARAM)["Parameter"]["Value"]
    image = ec2.describe_images(ImageIds=[ami])["Images"][0]
    assert image["Platform"] == "windows", (
        f"{_WINDOWS_AMI_PARAM} must resolve to a Windows image; {ami} reports "
        f"Platform={image.get('Platform')!r} Name={image.get('Name')!r}"
    )

    net = _public_network(ctx, ec2, az)
    profile = _ssm_instance_profile(ctx, iam)

    # --- one Windows instance, terminated by a cleanup registered immediately -
    tag_value = CHECK
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami,
            InstanceType=_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            SubnetId=net["subnet_id"],
            SecurityGroupIds=[net["group_id"]],
            IamInstanceProfile={"Name": profile},
            TagSpecifications=_tag_spec(ctx, tag_value, ("instance", "volume")),
        ),
        # A brand-new instance profile is not immediately resolvable by RunInstances.
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=30,
        delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {az!r}"
    )
    assert reservation["Instances"][0].get("Platform") == "windows", (
        f"EC2 must record this instance as a Windows platform instance, got "
        f"{reservation['Instances'][0].get('Platform')!r}"
    )

    # --- the agent has to come up: a Windows host that never registers is a FAIL
    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(
        _agent_view,
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=1200,
        interval_s=10.0,
        what=f"the SSM agent on Windows instance {instance_id} reaching PingStatus Online",
    )
    assert info["PingStatus"] == "Online", f"instance {instance_id!r} is {info!r}"
    assert info["ResourceType"] == "EC2Instance", info
    assert info["PlatformType"] == "Windows", (
        f"a Windows Server host must register as PlatformType Windows, got "
        f"{info.get('PlatformType')!r} for {instance_id!r}"
    )
    assert "Windows" in info.get("PlatformName", ""), (
        f"the agent must report a Windows PlatformName, got {info.get('PlatformName')!r}"
    )
    assert info.get("ComputerName"), (
        f"a registered node must report the host's own computer name, got {info!r}"
    )

    described = ec2.describe_instances(
        InstanceIds=[instance_id]
    )["Reservations"][0]["Instances"][0]

    # --- the guest speaks: PowerShell, IMDSv2, its own identity --------------
    expected_calc = str(_SEED * 5 + 2)
    out = _powershell(ssm, instance_id, [
        "$ErrorActionPreference='Stop'",
        "$t=Invoke-RestMethod -Method PUT -Uri http://169.254.169.254/latest/api/token "
        "-Headers @{'X-aws-ec2-metadata-token-ttl-seconds'='120'}",
        "$h=@{'X-aws-ec2-metadata-token'=$t}",
        "'IID=' + (Invoke-RestMethod -Headers $h "
        "-Uri http://169.254.169.254/latest/meta-data/instance-id)",
        "'LHOST=' + (Invoke-RestMethod -Headers $h "
        "-Uri http://169.254.169.254/latest/meta-data/local-hostname)",
        "'LIP=' + (Invoke-RestMethod -Headers $h "
        "-Uri http://169.254.169.254/latest/meta-data/local-ipv4)",
        "'CN=' + $env:COMPUTERNAME",
        "'PSMAJOR=' + $PSVersionTable.PSVersion.Major",
        "'CAPTION=' + (Get-CimInstance Win32_OperatingSystem).Caption",
        "'EC2LAUNCH=' + (Test-Path 'C:\\Program Files\\Amazon\\EC2Launch\\EC2Launch.exe')",
        f"'CALC=' + ({_SEED}*5+2)",
    ])
    guest = _kv(out["StandardOutputContent"])

    assert out["DocumentName"] == "AWS-RunPowerShellScript", out
    assert out["ResponseCode"] == 0, (
        f"the PowerShell script exited {out['ResponseCode']!r}: "
        f"stderr={out.get('StandardErrorContent')!r}"
    )
    assert out["StandardErrorContent"] == "", (
        f"the PowerShell script wrote to stderr: {out['StandardErrorContent']!r}"
    )
    # Only a real PowerShell host produces $PSVersionTable; ordering, not a pinned version.
    assert int(guest["PSMAJOR"]) >= 5, (
        f"the guest must run PowerShell 5 or newer (Windows Server 2022 ships 5.1); "
        f"$PSVersionTable.PSVersion.Major was {guest.get('PSMAJOR')!r}"
    )
    assert guest["CALC"] == expected_calc, (
        f"the guest had to compute {expected_calc!r} from the seed; it returned "
        f"{guest.get('CALC')!r} — a canned invocation record cannot produce this"
    )
    assert guest["EC2LAUNCH"] == "True", (
        "EC2Launch v2 must be installed in the guest of an AWS-published Windows AMI; "
        f"Test-Path returned {guest.get('EC2LAUNCH')!r}"
    )

    # the four cross-boundary equalities
    assert guest["IID"] == instance_id, (
        f"the guest's own IMDSv2 view reports instance-id {guest.get('IID')!r}, but "
        f"RunInstances minted {instance_id!r}"
    )
    assert guest["LIP"] == described["PrivateIpAddress"], (
        f"IMDS local-ipv4 in the guest was {guest.get('LIP')!r}, DescribeInstances says "
        f"{described['PrivateIpAddress']!r}"
    )
    assert guest["LHOST"] == described["PrivateDnsName"], (
        f"IMDS local-hostname in the guest was {guest.get('LHOST')!r}, DescribeInstances says "
        f"{described['PrivateDnsName']!r}"
    )
    # SSM reports the NetBIOS name plus its workgroup ("EC2AMAZ-XXXXXXX.WORKGROUP"); the guest's
    # %COMPUTERNAME% is the same name without the workgroup suffix.
    assert info["ComputerName"].split(".")[0] == guest["CN"], (
        f"SSM reports ComputerName {info['ComputerName']!r} for this host, but the guest's own "
        f"$env:COMPUTERNAME is {guest.get('CN')!r} — the EC2Launch-assigned name must be the "
        f"name the agent registers"
    )
    assert info["PlatformName"] == guest["CAPTION"], (
        f"SSM reports PlatformName {info['PlatformName']!r} but the guest's "
        f"Win32_OperatingSystem.Caption is {guest.get('CAPTION')!r}"
    )

    # --- absence: the Linux document is refused, and leaves no invocation ----
    code, message = _error(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": ["echo hi"]},
            TimeoutSeconds=120,
        )
    )
    assert code == "UnsupportedPlatformType", (
        f"a Linux-only document sent to a Windows host must be refused with "
        f"UnsupportedPlatformType, got {code!r}"
    )
    expected_message = "Cannot perform operation for instance id with unsupported platform type."
    assert message == expected_message, (
        f"the refusal must carry SSM's exact message {expected_message!r}, got {message!r}"
    )

    invocations = []
    for page in ssm.get_paginator("list_command_invocations").paginate(
        InstanceId=instance_id, Details=False
    ):
        invocations += page["CommandInvocations"]
    documents = sorted({i["DocumentName"] for i in invocations})
    # Scoped to an instance this check created, so "exactly these" is a property of the query.
    assert documents == ["AWS-RunPowerShellScript"], (
        "the refused command must leave no invocation on the instance; the invocations recorded "
        f"against {instance_id!r} name documents {documents!r}"
    )
    assert [i["Status"] for i in invocations] == ["Success"], (
        f"the positive control must be the only invocation, and it must have succeeded: "
        f"{[(i['DocumentName'], i['Status']) for i in invocations]!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available and
    must not be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
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


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
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


def _retry_delete(fn, codes=("DependencyViolation", "InvalidParameterValue", "DeleteConflict"),
                  attempts=20, delay=10.0):
    """Deletes that can only succeed once a reference is released. ctx.on_cleanup swallows
    exceptions, so a leak here would be silent — retry, then let the final raise surface."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound") or code in ("NoSuchEntity", "InvalidGroup.NotFound"):
                return None
            if code in codes and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise
    raise last


def _tag_spec(ctx, value, resource_types):
    """EC2 resources are found for cleanup only through their tags."""
    return [
        {"ResourceType": rt,
         "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dwin-")},
                  {"Key": "sim2real", "Value": value}]}
        for rt in resource_types
    ]


def _usable_az(ec2, instance_type):
    """An AZ that both is available and offers the instance type. Neither catalogue answers
    both questions, and a hardcoded AZ name is a different physical zone in another account."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in this region offers {instance_type}; offered {sorted(offered)!r}, "
        f"available {sorted(available)!r}"
    )
    return usable[0]


def _public_network(ctx, ec2, az):
    """A VPC, public subnet, route to an internet gateway and a security group, all created
    here: the SSM agent must reach the SSM endpoints to register, and an ambient default VPC is
    account configuration this check must not depend on."""
    value = CHECK
    vpc = ec2.create_vpc(
        CidrBlock="10.88.0.0/16", TagSpecifications=_tag_spec(ctx, value, ("vpc",)),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(
        TagSpecifications=_tag_spec(ctx, value, ("internet-gateway",)),
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_internet_gateway(
        InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.detach_internet_gateway(
        InternetGatewayId=igw, VpcId=vpc)))

    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.88.1.0/24", AvailabilityZone=az,
        TagSpecifications=_tag_spec(ctx, value, ("subnet",)),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})

    table = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=_tag_spec(ctx, value, ("route-table",)),
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=table)))
    ec2.create_route(RouteTableId=table, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=table, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.disassociate_route_table(
        AssociationId=assoc)))

    group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-dwin-sg-"), Description="sim2real dwin windows guest",
        VpcId=vpc, TagSpecifications=_tag_spec(ctx, value, ("security-group",)),
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=group)))
    return {"vpc_id": vpc, "subnet_id": subnet, "group_id": group}


def _ssm_instance_profile(ctx, iam):
    """An instance profile granting only AmazonSSMManagedInstanceCore, created here and torn
    down in the order IAM requires (a role still held by a profile cannot be deleted)."""
    name = ctx.unique_name("sim2real-dwin-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real dwin windows guest run-command role",
                    Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _drop_role():
        _retry_delete(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY))
        _retry_delete(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)

    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _drop_profile():
        _retry_delete(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=name, RoleName=name))
        _retry_delete(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    ctx.on_cleanup(_drop_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait until the instance has left `running`, so the network and the instance
    profile it references can then be deleted."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [
            i["State"]["Name"]
            for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            for i in r["Instances"]
        ]
        if all(s == "terminated" for s in states):
            return
        time.sleep(10)


def _powershell(ssm, instance_id, lines, timeout_s=600):
    """Send one AWS-RunPowerShellScript command and return its completed invocation."""
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": lines},
            TimeoutSeconds=600,
            Comment="sim2real dwin windows guest",
        )
    )
    command_id = sent["Command"]["CommandId"]
    assert sent["Command"]["Status"] == "Pending", (
        f"a freshly accepted command must be Pending, got {sent['Command']['Status']!r}"
    )

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(
        _invocation,
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=timeout_s,
        interval_s=5.0,
        what=f"invocation {command_id} on {instance_id} reaching a terminal status",
    )
    assert inv["Status"] == "Success", (
        f"the PowerShell invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stdout={inv.get('StandardOutputContent')!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["InstanceId"] == instance_id, (
        f"the invocation reports instance {inv['InstanceId']!r}, expected {instance_id!r}"
    )
    return inv


def _kv(stdout):
    """`KEY=value` lines from a PowerShell invocation's stdout (CRLF-terminated)."""
    out = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            out[key] = value
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
