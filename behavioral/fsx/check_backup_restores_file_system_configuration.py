"""backup-restores-file-system-configuration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-restores-file-system-configuration"
GROUP = 'backups'
SERVICES = ['fsx']

_VPC_CIDR = '10.0.0.0/16'
_INITIAL_GIB = 64          # the documented minimum for an OpenZFS SINGLE_AZ_1 file system
_THROUGHPUT_MBPS = 64      # the lowest value SINGLE_AZ_1 accepts
_CREATE_TIMEOUT_S = 900.0
_BACKUP_TIMEOUT_S = 900.0
_DELETE_TIMEOUT_S = 900.0
_POLL_S = 2.0


# ===== helpers =====

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _own_network(ctx, ec2, label):
    """Build the VPC, security group and availability-zone list this check owns outright.

    The account's default VPC is shared state no check may lean on, and FSx refuses
    CreateFileSystem outright unless the security group admits inbound NFS on TCP 2049, so the
    ingress rule is part of the network rather than a nicety.
    """
    own = [{"Key": "sim2real", "Value": label},
           {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-fsx-")}]
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR,
                         TagSpecifications=[{"ResourceType": "vpc", "Tags": own}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc))
    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-fsx-"), VpcId=vpc,
        Description=f"sim2real-behav {label}",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": own}])["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg))
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": _VPC_CIDR,
                                          "Description": "sim2real-behav fsx nfs"}]}])
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    return vpc, sg, azs, own


def _create_file_system(ctx, fsx, ec2, vpc, sg, azs, own):
    """Create a 64 GiB OpenZFS SINGLE_AZ_1 file system in a subnet this check owns.

    The zone is derived, never named: zone ids are mapped per account, and not every zone offers
    every FSx deployment type, so each candidate gets its own subnet and its own attempt.
    """
    last = None
    for i, az in enumerate(azs[:3]):
        subnet = ec2.create_subnet(
            VpcId=vpc, CidrBlock=f"10.0.{i + 1}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": own}])["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet: _delete_net(ec2, "delete_subnet", SubnetId=s))
        try:
            fs = fsx.create_file_system(
                FileSystemType="OPENZFS", StorageCapacity=_INITIAL_GIB, SubnetIds=[subnet],
                SecurityGroupIds=[sg], Tags=own,
                OpenZFSConfiguration={"DeploymentType": "SINGLE_AZ_1",
                                      "ThroughputCapacity": _THROUGHPUT_MBPS,
                                      "AutomaticBackupRetentionDays": 0,
                                      "RootVolumeConfiguration": {"DataCompressionType": "ZSTD",
                                                                  "RecordSizeKiB": 128}},
            )["FileSystem"]
        except ClientError as exc:
            last = exc
            continue
        ctx.on_cleanup(lambda i=fs["FileSystemId"]: _delete_file_system(fsx, i))
        return fs, subnet
    raise AssertionError(
        f"no zone in {azs[:3]} accepted a {_INITIAL_GIB} GiB OpenZFS SINGLE_AZ_1 file system, so "
        f"the backup and restore under test were never reachable; last refusal: {last}")


def _delete_file_system(fsx, fsid):
    """Delete with no final backup. An already-absent file system is success, so this re-runs."""
    try:
        fsx.delete_file_system(FileSystemId=fsid, OpenZFSConfiguration={
            "SkipFinalBackup": True, "Options": ["DELETE_CHILD_VOLUMES_AND_SNAPSHOTS"]})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "FileSystemNotFound":
            raise


def _delete_backup(fsx, backup_id):
    """Backstop for the backup. An already-absent backup is success, so this re-runs."""
    try:
        fsx.delete_backup(BackupId=backup_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "BackupNotFound":
            raise


def _describe(fsx, fsid):
    return fsx.describe_file_systems(FileSystemIds=[fsid])["FileSystems"][0]


def _wait_available(fsx, fsid, timeout_s: float = _CREATE_TIMEOUT_S):
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        d = _describe(fsx, fsid)
        seen.append(d["Lifecycle"])
        if d["Lifecycle"] == "AVAILABLE":
            return d
        assert d["Lifecycle"] != "FAILED", (
            f"{fsid} went to FAILED: {d.get('FailureDetails')}")
        time.sleep(_POLL_S)
    raise AssertionError(f"{fsid} never became AVAILABLE within {timeout_s:.0f}s; saw {seen}")


def _wait_backup(fsx, backup_id, timeout_s: float = _BACKUP_TIMEOUT_S):
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        b = fsx.describe_backups(BackupIds=[backup_id])["Backups"][0]
        seen.append(b["Lifecycle"])
        if b["Lifecycle"] == "AVAILABLE":
            return b
        assert b["Lifecycle"] != "FAILED", (
            f"{backup_id} went to FAILED: {b.get('FailureDetails')}")
        time.sleep(_POLL_S)
    raise AssertionError(f"{backup_id} never became AVAILABLE within {timeout_s:.0f}s; saw {seen}")


def _openzfs_shape(fs):
    """The configuration fields DescribeFileSystems reports for both a source and a restore."""
    cfg = fs["OpenZFSConfiguration"]
    return {"FileSystemType": fs["FileSystemType"],
            "StorageCapacity": fs["StorageCapacity"],
            "StorageType": fs["StorageType"],
            "DeploymentType": cfg["DeploymentType"],
            "ThroughputCapacity": cfg["ThroughputCapacity"],
            "DiskIopsMode": cfg["DiskIopsConfiguration"]["Mode"],
            "DiskIops": cfg["DiskIopsConfiguration"]["Iops"]}


def _teardown(ctx, fsx, file_systems, timeout_s: float = _DELETE_TIMEOUT_S):
    """Delete the file systems inside the check body, where the budget is the check's own.

    An FSx file system takes minutes to disappear, and its ENIs hold the subnet and security group
    until it does; every delete is issued before anything is waited on. The registered network
    teardowns then remove the VPC.
    """
    for fsid in file_systems:
        _delete_file_system(fsx, fsid)
    for fsid in file_systems:
        left = ctx.time_left()
        budget = timeout_s if left is None else min(timeout_s, left)
        deadline = time.monotonic() + budget
        while True:
            try:
                _describe(fsx, fsid)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "FileSystemNotFound":
                    break
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(f"file system {fsid} still present {budget:.0f}s after DeleteFileSystem")
            time.sleep(_POLL_S)


# ===== check =====

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A backup records its file system's configuration, and a restore with no OpenZFSConfiguration
    yields a NEW file system (new id, DNS name, root volume) with that same configuration.
    DeleteBackup is refused with BackupInProgress while the backup is still CREATING."""
    fsx = ctx.client("fsx")
    ec2 = ctx.client("ec2")

    vpc, sg, azs, own = _own_network(ctx, ec2, CHECK)
    created, subnet = _create_file_system(ctx, fsx, ec2, vpc, sg, azs, own)
    source_id = created["FileSystemId"]
    source = _wait_available(fsx, source_id)

    started = fsx.create_backup(FileSystemId=source_id, Tags=own)["Backup"]
    backup_id = started["BackupId"]
    ctx.on_cleanup(lambda: _delete_backup(fsx, backup_id))
    assert started["Type"] == "USER_INITIATED", (
        f"a backup taken through CreateBackup reported Type {started['Type']!r}")
    assert started["Lifecycle"] == "CREATING", (
        f"CreateBackup returned Lifecycle {started['Lifecycle']!r}; a backup is taken "
        f"asynchronously and starts CREATING")

    refused, message = _error(lambda: fsx.delete_backup(BackupId=backup_id))
    assert refused == "BackupInProgress", (
        f"DeleteBackup on a backup that is still being taken returned {refused!r}, not the "
        f"BackupInProgress that protects it")
    expected_message = f"Backup {backup_id} cannot be deleted while it is in CREATING state."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}")

    settled = _wait_backup(fsx, backup_id)
    assert settled["ProgressPercent"] == 100, (
        f"an AVAILABLE backup reported ProgressPercent {settled.get('ProgressPercent')!r}")
    embedded = settled["FileSystem"]
    assert embedded["FileSystemId"] == source_id, (
        f"the backup names file system {embedded['FileSystemId']} as its source, not {source_id}")
    assert _openzfs_shape(embedded) == _openzfs_shape(source), (
        f"the backup's embedded configuration {_openzfs_shape(embedded)} is not the source file "
        f"system's {_openzfs_shape(source)} — the backup must record what it was taken from")

    # The restore states the network and the tags, and nothing else: every OpenZFS setting has to
    # come from the backup.
    restored = fsx.create_file_system_from_backup(
        BackupId=backup_id, SubnetIds=[subnet], SecurityGroupIds=[sg], Tags=own)["FileSystem"]
    restored_id = restored["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_file_system(fsx, restored_id))
    assert restored_id != source_id, (
        "CreateFileSystemFromBackup returned the source file system's own id — a restore is a new "
        "file system")
    assert restored["Lifecycle"] == "CREATING", (
        f"CreateFileSystemFromBackup returned Lifecycle {restored['Lifecycle']!r}")
    assert _openzfs_shape(restored) == _openzfs_shape(source), (
        f"the restore request carried no OpenZFSConfiguration and came back as "
        f"{_openzfs_shape(restored)}, not the backed-up {_openzfs_shape(source)}")

    live = _wait_available(fsx, restored_id)
    assert _openzfs_shape(live) == _openzfs_shape(source), (
        f"once AVAILABLE the restored file system reported {_openzfs_shape(live)}, drifting from "
        f"the backed-up {_openzfs_shape(source)}")
    assert live["DNSName"] != source["DNSName"], (
        f"the restored file system answers on the source's DNS name {live['DNSName']}")
    assert (live["OpenZFSConfiguration"]["RootVolumeId"]
            != source["OpenZFSConfiguration"]["RootVolumeId"]), (
        f"the restore reused the source's root volume "
        f"{source['OpenZFSConfiguration']['RootVolumeId']} instead of creating its own")
    assert _describe(fsx, source_id)["Lifecycle"] == "AVAILABLE", (
        "taking a backup and restoring from it disturbed the source file system")

    # Positive control for the BackupInProgress refusal above: the same call, on the same backup,
    # once it has settled, is accepted and the backup goes away. The restored file system does not
    # depend on it.
    fsx.delete_backup(BackupId=backup_id)
    gone, message = _error(lambda: fsx.describe_backups(BackupIds=[backup_id]))
    assert gone == "BackupNotFound", (
        f"after a successful DeleteBackup the backup still reads back ({gone!r})")
    expected_message = f"Backup '{backup_id}' does not exist."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}")

    _teardown(ctx, fsx, [restored_id, source_id])


# EC2 network teardown: an FSx file system's ENIs outlive its delete call, so DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc answer DependencyViolation until they go. Wait for the ENIs and
# retry that code inside one window shared by the check's network deletes; raise everything else.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return None  # the in-body teardown already deleted it
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
