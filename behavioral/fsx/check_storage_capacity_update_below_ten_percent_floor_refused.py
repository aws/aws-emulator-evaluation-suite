"""storage-capacity-update-below-ten-percent-floor-refused."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "storage-capacity-update-below-ten-percent-floor-refused"
GROUP = 'file-systems'
SERVICES = ['fsx']

_VPC_CIDR = '10.0.0.0/16'
_INITIAL_GIB = 64          # the documented minimum for an OpenZFS SINGLE_AZ_1 file system
_THROUGHPUT_MBPS = 64      # the lowest value SINGLE_AZ_1 accepts
_DECREASE_GIB = 32         # below the current capacity
_SAME_GIB = 64             # equal to the current capacity
_TOO_SMALL_GIB = 65        # an increase, but inside the +10% floor (64 -> 70.4)
_TARGET_GIB = 71           # the smallest increase that clears the floor
_CREATE_TIMEOUT_S = 900.0
_CONVERGE_TIMEOUT_S = 900.0
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
        f"the capacity semantics under test were never reachable; last refusal: {last}")


def _delete_file_system(fsx, fsid):
    """Delete with no final backup. An already-absent file system is success, so this re-runs."""
    try:
        fsx.delete_file_system(FileSystemId=fsid, OpenZFSConfiguration={
            "SkipFinalBackup": True, "Options": ["DELETE_CHILD_VOLUMES_AND_SNAPSHOTS"]})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "FileSystemNotFound":
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
            f"{fsid} went to FAILED during creation: {d.get('FailureDetails')}")
        time.sleep(_POLL_S)
    raise AssertionError(f"{fsid} never became AVAILABLE within {timeout_s:.0f}s; saw {seen}")


def _teardown(ctx, fsx, fsid, timeout_s: float = _DELETE_TIMEOUT_S):
    """Delete the file system inside the check body, where the budget is the check's own.

    An FSx file system takes minutes to disappear, and its ENIs hold the subnet and security group
    until it does; the registered network teardowns then remove the VPC.
    """
    _delete_file_system(fsx, fsid)
    left = ctx.time_left()
    budget = timeout_s if left is None else min(timeout_s, left)
    deadline = time.monotonic() + budget
    while True:
        try:
            _describe(fsx, fsid)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "FileSystemNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"file system {fsid} still present {budget:.0f}s after DeleteFileSystem")
        time.sleep(_POLL_S)


# ===== check =====

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A storage-capacity update inside FSx's +10% floor is refused and moves nothing; the smallest
    increase above it is accepted as a pending FILE_SYSTEM_UPDATE action, and the reported
    capacity changes only when that action reaches COMPLETED."""
    fsx = ctx.client("fsx")
    ec2 = ctx.client("ec2")

    vpc, sg, azs, own = _own_network(ctx, ec2, CHECK)
    created, subnet = _create_file_system(ctx, fsx, ec2, vpc, sg, azs, own)
    fsid = created["FileSystemId"]
    assert created["StorageCapacity"] == _INITIAL_GIB, (
        f"CreateFileSystem reported {created['StorageCapacity']} GiB, not the requested "
        f"{_INITIAL_GIB}")
    _wait_available(fsx, fsid)

    for target in (_DECREASE_GIB, _SAME_GIB, _TOO_SMALL_GIB):
        code, message = _error(lambda t=target: fsx.update_file_system(FileSystemId=fsid,
                                                                      StorageCapacity=t))
        assert code == "BadRequest", (
            f"UpdateFileSystem to {target} GiB from {_INITIAL_GIB} GiB returned {code!r}; FSx "
            f"requires a target at least 10% above the current capacity and answers BadRequest")
        expected_message = (
            f"Invalid desired storage capacity provided: {target} GiB. Desired storage capacity "
            f"must be at least 10% higher than the existing value of {_INITIAL_GIB} GiB.")
        assert message == expected_message, (
            f"expected message {expected_message!r}, got {message!r}")

    settled = _describe(fsx, fsid)
    assert settled["StorageCapacity"] == _INITIAL_GIB, (
        f"a refused update moved the capacity to {settled['StorageCapacity']} GiB — a rejection "
        f"must leave the file system exactly as it was")
    assert not settled.get("AdministrativeActions"), (
        f"a refused update recorded administrative actions {settled.get('AdministrativeActions')}"
        f"; FSx records none for work it never accepted")

    # Positive control: the same operation, one GiB above the floor, is accepted.
    accepted = fsx.update_file_system(FileSystemId=fsid,
                                      StorageCapacity=_TARGET_GIB)["FileSystem"]
    assert accepted["StorageCapacity"] == _INITIAL_GIB, (
        f"UpdateFileSystem's own response already reported {accepted['StorageCapacity']} GiB; the "
        f"accepted target is pending work, not an applied value")
    pending = [a for a in accepted.get("AdministrativeActions", [])
               if a["AdministrativeActionType"] == "FILE_SYSTEM_UPDATE"]
    assert len(pending) == 1, (
        f"the accepted update reported {len(pending)} FILE_SYSTEM_UPDATE actions, expected 1: "
        f"{accepted.get('AdministrativeActions')}")
    assert pending[0]["TargetFileSystemValues"]["StorageCapacity"] == _TARGET_GIB, (
        f"the pending action targets {pending[0]['TargetFileSystemValues']} rather than the "
        f"{_TARGET_GIB} GiB that was requested")

    deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    samples = []
    while time.monotonic() < deadline:
        d = _describe(fsx, fsid)
        act = [a for a in d.get("AdministrativeActions", [])
               if a["AdministrativeActionType"] == "FILE_SYSTEM_UPDATE"]
        assert len(act) == 1, (
            f"while the update was in flight the file system reported {len(act)} "
            f"FILE_SYSTEM_UPDATE actions, expected exactly 1: {d.get('AdministrativeActions')}")
        samples.append((act[0]["Status"], d["StorageCapacity"], d["Lifecycle"]))
        if act[0]["Status"] == "COMPLETED":
            break
        time.sleep(_POLL_S)
    else:
        raise AssertionError(
            f"the FILE_SYSTEM_UPDATE action never reached COMPLETED within "
            f"{_CONVERGE_TIMEOUT_S:.0f}s; saw {samples}")

    unfinished = [s for s in samples if s[0] != "COMPLETED"]
    assert all(s[1] == _INITIAL_GIB for s in unfinished), (
        f"the file system reported the new capacity before its action completed: {samples}")
    assert all(s[2] == "AVAILABLE" for s in samples), (
        f"a storage-capacity increase took the file system out of AVAILABLE: {samples}")
    assert samples[-1][1] == _TARGET_GIB, (
        f"the action completed but the capacity read back as {samples[-1][1]} GiB, not "
        f"{_TARGET_GIB}")

    final = _describe(fsx, fsid)
    assert final["StorageCapacity"] == _TARGET_GIB, (
        f"a second read after convergence reported {final['StorageCapacity']} GiB")
    assert final["OpenZFSConfiguration"]["ThroughputCapacity"] == _THROUGHPUT_MBPS, (
        f"the capacity update also changed throughput to "
        f"{final['OpenZFSConfiguration']['ThroughputCapacity']} MB/s — it must change only what "
        f"was asked for")
    assert final["OpenZFSConfiguration"]["DeploymentType"] == "SINGLE_AZ_1", (
        f"the capacity update also changed the deployment type to "
        f"{final['OpenZFSConfiguration']['DeploymentType']}")

    _teardown(ctx, fsx, fsid)


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
