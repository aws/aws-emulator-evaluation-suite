"""efs-nfs-mount-write-read-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "efs-nfs-mount-write-read-round-trip"
GROUP = "native-protocol"
SERVICES = ["efs"]

_SSM_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """A file written over the real NFSv4 mount from an EC2 instance is read back byte-for-byte via
    SSM, and the mount is proven to actually be NFS (not merely a local filesystem that would
    satisfy the same write/read round trip)."""
    efs = ctx.client("efs")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    # --- EFS file system + mount target ---
    token = ctx.unique_name("sim2real-efs-nfs-")
    fs_id = efs.create_file_system(
        CreationToken=token,
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "Name", "Value": token}],
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_verified(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    # A dedicated VPC, not an adopted ambient one: this account may have no default VPC, and an
    # ambient non-default VPC left by another concurrent check is not guaranteed to have Amazon's
    # DNS resolution switched on -- and the EFS mount target is addressed by an Amazon-managed DNS
    # name, so without it `mount.nfs4` fails "Name or service not known" no matter how long you
    # wait. Provisioning our own removes the dependency on that ambient state entirely.
    net = _provision_network(ctx, ec2)
    vpc_id = net["vpc_id"]
    ctx.on_cleanup(lambda: _delete_network_verified(ec2, net))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-efs-nfs-sg-"),
        Description="sim2real EFS NFS round-trip test",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049, "UserIdGroupPairs": [{"GroupId": sg_id}]}
        ],
    )
    ctx.on_cleanup(lambda: _delete_sg_verified(ec2, sg_id))

    role_name = ctx.unique_name("sim2real-efs-nfs-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _delete_role_verified(iam, role_name))

    mt_id = efs.create_mount_target(FileSystemId=fs_id, SubnetId=net["subnet_id"], SecurityGroups=[sg_id])[
        "MountTargetId"
    ]
    ctx.on_cleanup(lambda: _delete_mt_verified(efs, mt_id))
    _wait_mt_state(efs, mt_id, "available")
    mt_ip = efs.describe_mount_targets(MountTargetId=mt_id)["MountTargets"][0]["IpAddress"]

    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")[
        "Parameter"
    ]["Value"]

    instance_id = _launch_instance(ctx, ec2, ami_id, net["subnet_id"], sg_id, role_name)
    ctx.on_cleanup(lambda: _terminate_instance_verified(ec2, instance_id))

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    _wait_ssm_online(ssm, instance_id, timeout_s=300.0)

    marker = ctx.unique_name("sim2real-efs-payload-")
    mount_point = "/mnt/sim2real-efs-test"
    # Mount by the mount target's own IP address, not its Amazon-managed DNS name: `DescribeMountTargets`
    # already reported LifeCycleState=available, but that promise covers the NFS server itself, not
    # how fast every Amazon-provided DNS resolver in the VPC picks up the new record -- and mounting
    # is what this check exists to test, not EFS's private DNS delivery.
    nfs_target = f"{mt_ip}:/"
    script = (
        f"set -e\n"
        f"sudo mkdir -p {mount_point}\n"
        f"MOUNT_OK=0\n"
        f"for i in $(seq 1 6); do\n"
        f"  if sudo mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,"
        f"retrans=2,noresvport {nfs_target} {mount_point}; then MOUNT_OK=1; break; fi\n"
        f"  echo \"mount attempt $i failed, retrying in 10s\" >&2\n"
        f"  sleep 10\n"
        f"done\n"
        f"if [ \"$MOUNT_OK\" -ne 1 ]; then echo 'mount never succeeded within the retry window' >&2; exit 32; fi\n"
        f"echo '{marker}' | sudo tee {mount_point}/roundtrip.txt >/dev/null\n"
        f"echo SIM2REAL_CONTENT:$(sudo cat {mount_point}/roundtrip.txt)\n"
        f"echo SIM2REAL_FSTYPE:$(findmnt -no FSTYPE {mount_point})\n"
        f"echo SIM2REAL_MAGIC:$(stat -f -c %T {mount_point})\n"
        f"sudo umount {mount_point}\n"
    )

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]},
        TimeoutSeconds=180,
    )["Command"]["CommandId"]

    invocation = _wait_ssm_command(ssm, command_id, instance_id, timeout_s=240.0)
    assert invocation["Status"] == "Success", (
        f"NFS mount/write/read script failed: {invocation.get('StandardErrorContent')}"
    )
    stdout = invocation["StandardOutputContent"]

    content_line = _output_line(stdout, "SIM2REAL_CONTENT:")
    assert content_line is not None and marker in content_line, (
        f"expected marker {marker!r} in the file read back over NFS, got: {content_line!r}"
    )

    # A `mount -t nfs4` that silently landed on a local filesystem (or an emulator that answers
    # the write/read round trip without a real NFS server behind it) would satisfy the assertion
    # above identically -- so the mount itself has to be proven to be NFS, independently.
    fstype = _output_line(stdout, "SIM2REAL_FSTYPE:")
    assert fstype == "nfs4", (
        f"findmnt reports filesystem type {fstype!r} for {mount_point}, expected 'nfs4' -- a "
        f"non-NFS mount (e.g. tmpfs) would pass the write/read round trip above for the wrong reason"
    )
    magic = _output_line(stdout, "SIM2REAL_MAGIC:")
    assert magic == "nfs", (
        f"statfs magic for {mount_point} is {magic!r}, expected 'nfs'"
    )

    # --- verified teardown, INLINE, inside the check's own (much larger) body budget ---
    # `simparity.behavioral.harness.DEFAULT_CLEANUP_TIMEOUT_S` is 60.0 and bounds the WHOLE LIFO
    # chain of registered `ctx.on_cleanup` callbacks on a daemon thread. Terminating this instance
    # and waiting out its mount target's deletion alone exceeds that, so the registered chain
    # would be cut off mid-way on every run and the check would report PASS while leaking an EC2
    # instance and an EFS file system. Deleting here, before the check returns, puts the teardown
    # under the check's own (300s) budget instead. The registered cleanups stay as the
    # failure-path safety net; each tolerates the resource already being gone.
    _terminate_instance_verified(ec2, instance_id)
    _delete_mt_verified(efs, mt_id)
    _delete_fs_verified(efs, fs_id)
    _delete_sg_verified(ec2, sg_id)
    _delete_role_verified(iam, role_name)
    _delete_network_verified(ec2, net)
    assert efs.describe_file_systems(CreationToken=token)["FileSystems"] == [], (
        f"the file system created under token {token!r} is still listed after a verified delete"
    )


# ===== shared helpers =====
def _output_line(stdout, prefix):
    line = next((ln for ln in stdout.splitlines() if ln.startswith(prefix)), None)
    return line[len(prefix):].strip() if line is not None else None


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_fs_state(efs, fs_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _wait_mt_state(efs, mt_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_mount_targets(MountTargetId=mt_id)["MountTargets"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _provision_network(ctx, ec2):
    """A minimal, dedicated VPC: one /24, one public subnet, an IGW and a default route.

    EC2 needs the public route for SSM to reach its endpoints (there is no VPC endpoint here),
    and both DNS attributes are set explicitly rather than relied on as VPC creation defaults --
    the EFS mount target's Amazon-managed DNS name will not resolve without them.
    """
    cidr = "10.91.0.0/24"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [
                    {"Key": "sim2real", "Value": CHECK},
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-efs-nfs-vpc-")},
                ],
            }
        ],
    )["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "sim2real", "Value": CHECK}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]

    return {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "igw_id": igw_id,
        "rtb_id": rtb_id,
        "assoc_id": assoc_id,
    }


def _delete_network_verified(ec2, net):
    try:
        ec2.disassociate_route_table(AssociationId=net["assoc_id"])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidAssociationID.NotFound":
            print(f"LEAK: could not disassociate route table {net['rtb_id']}: {e}")
            raise
    try:
        ec2.delete_route_table(RouteTableId=net["rtb_id"])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidRouteTableID.NotFound":
            print(f"LEAK: could not delete route table {net['rtb_id']}: {e}")
            raise
    try:
        ec2.detach_internet_gateway(InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    except ClientError as e:
        if e.response["Error"]["Code"] not in (
            "Gateway.NotAttached",
            "InvalidInternetGatewayID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            print(f"LEAK: could not detach internet gateway {net['igw_id']}: {e}")
            raise
    try:
        ec2.delete_internet_gateway(InternetGatewayId=net["igw_id"])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInternetGatewayID.NotFound":
            print(f"LEAK: could not delete internet gateway {net['igw_id']}: {e}")
            raise
    try:
        ec2.delete_subnet(SubnetId=net["subnet_id"])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            print(f"LEAK: could not delete subnet {net['subnet_id']}: {e}")
            raise

    deadline = time.monotonic() + 60.0
    last = None
    while time.monotonic() < deadline:
        try:
            ec2.delete_vpc(VpcId=net["vpc_id"])
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                return
            last = e
            time.sleep(5.0)
    print(f"LEAK: vpc {net['vpc_id']} could not be deleted: {last}")
    raise AssertionError(f"vpc {net['vpc_id']} could not be deleted: {last}")


def _launch_instance(ctx, ec2, ami_id, subnet_id, sg_id, role_name):
    deadline = time.monotonic() + 60.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": role_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": ctx.unique_name("sim2real-efs-nfs-")},
                            {"Key": "sim2real", "Value": CHECK},
                        ],
                    }
                ],
            )
            return resp["Instances"][0]["InstanceId"]
        except ClientError as e:
            last_error = e
            if e.response["Error"]["Code"] in ("InvalidParameterValue", "Invalid"):
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(f"could not launch EC2 instance (IAM propagation?): {last_error}")


def _wait_ssm_online(ssm, instance_id, timeout_s=300.0):
    def probe():
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        return info[0]["PingStatus"] if info else None

    return _poll_until(probe, lambda s: s == "Online", timeout_s=timeout_s, interval_s=10.0)


def _wait_ssm_command(ssm, command_id, instance_id, timeout_s=240.0):
    terminal = {"Success", "Failed", "Cancelled", "TimedOut"}

    def probe():
        # SendCommand returns before the per-instance invocation is registered, so the first few
        # GetCommandInvocation calls raise InvocationDoesNotExist. That is registration latency,
        # not a missing command; every other error is real and propagates.
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvocationDoesNotExist":
                return None
            raise

    return _poll_until(
        probe, lambda inv: inv is not None and inv["Status"] in terminal, timeout_s=timeout_s, interval_s=5.0
    )


def _terminate_instance_verified(ec2, instance_id, timeout_s=300.0):
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            print(f"LEAK: could not terminate instance {instance_id}: {e}")
            raise
        return
    try:
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
        )
    except Exception as e:
        print(f"LEAK: instance {instance_id} did not reach terminated within {timeout_s}s: {e}")
        raise


def _delete_mt_verified(efs, mt_id, timeout_s=180.0):
    try:
        efs.delete_mount_target(MountTargetId=mt_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "MountTargetNotFound":
            print(f"LEAK: delete_mount_target({mt_id}) failed: {e}")
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            efs.describe_mount_targets(MountTargetId=mt_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "MountTargetNotFound":
                return
        time.sleep(5.0)
    print(f"LEAK: mount target {mt_id} still present after {timeout_s}s")
    raise AssertionError(f"mount target {mt_id} still present after {timeout_s}s")


def _delete_fs_verified(efs, fs_id, timeout_s=180.0):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "FileSystemNotFound":
            print(f"LEAK: delete_file_system({fs_id}) failed: {e} -- EFS bills $0.30/GiB-month")
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            efs.describe_file_systems(FileSystemId=fs_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "FileSystemNotFound":
                return
        time.sleep(5.0)
    print(f"LEAK: file system {fs_id} still present after {timeout_s}s")
    raise AssertionError(f"file system {fs_id} still present after {timeout_s}s")


def _delete_sg_verified(ec2, sg_id, timeout_s=420.0):
    # DependencyViolation until the mount target's and the instance's ENIs are actually released,
    # which lags MountTargetNotFound and instance_terminated by minutes.
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
                return
            last = e
            time.sleep(10.0)
    print(f"LEAK: security group {sg_id} could not be deleted: {last}")
    raise AssertionError(f"security group {sg_id} could not be deleted: {last}")


def _delete_role_verified(iam, role_name):
    for call in (
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name),
        lambda: iam.delete_instance_profile(InstanceProfileName=role_name),
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            call()
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                print(f"LEAK: IAM teardown step failed for {role_name}: {e}")
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
