"""data-repository-association-invalid-repository-path-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-repository-association-invalid-repository-path-rejected"
GROUP = 'data-repository'
SERVICES = ['fsx']

_VPC_CIDR = '10.1.0.0/16'
_STORAGE_GIB = 1200  # the documented minimum for a LUSTRE SCRATCH_2 file system
_LUSTRE_VERSION = '2.12'  # the minimum Lustre version that supports data repository associations
_DELETE_TIMEOUT_S = 600.0
_POLL_S = 5.0



def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _own_network(ctx, ec2, label):
    """Build the VPC and security group this check owns outright.

    FSx refuses CreateFileSystem unless the security group admits the file system's own data
    plane traffic, so the ingress rule is part of the network rather than a nicety.
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
                                          "Description": "sim2real-behav fsx data plane"}]}])
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    return vpc, sg, azs, own


def _create_file_system(ctx, fsx, ec2, vpc, sg, azs, own):
    """Request a 1.2 TiB LUSTRE SCRATCH_2 file system in a subnet this check owns, without
    waiting for it to settle: every assertion here targets what FSx validates up front, before
    the file system ever reaches AVAILABLE.
    """
    last = None
    for i, az in enumerate(azs[:3]):
        subnet = ec2.create_subnet(
            VpcId=vpc, CidrBlock=f"10.1.{i + 1}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": own}])["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet: _delete_net(ec2, "delete_subnet", SubnetId=s))
        try:
            fs = fsx.create_file_system(
                FileSystemType="LUSTRE", FileSystemTypeVersion=_LUSTRE_VERSION,
                StorageCapacity=_STORAGE_GIB, SubnetIds=[subnet],
                SecurityGroupIds=[sg], Tags=own,
                LustreConfiguration={"DeploymentType": "SCRATCH_2"},
            )["FileSystem"]
        except ClientError as exc:
            last = exc
            continue
        ctx.on_cleanup(lambda i=fs["FileSystemId"]: _cancel_file_system(fsx, i))
        return fs, subnet
    raise AssertionError(
        f"no zone in {azs[:3]} accepted a {_STORAGE_GIB} GiB LUSTRE SCRATCH_2 file system; "
        f"last refusal: {last}")


def _cancel_file_system(fsx, fsid):
    """An already-absent file system is success, so this re-runs."""
    try:
        fsx.delete_file_system(FileSystemId=fsid)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "FileSystemNotFound":
            raise


def _wait_gone(fsx, fsid, timeout_s: float = _DELETE_TIMEOUT_S, poll_s: float = _POLL_S):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            fsx.describe_file_systems(FileSystemIds=[fsid])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "FileSystemNotFound":
                return
            raise
        time.sleep(poll_s)
    raise AssertionError(f"{fsid} still present {timeout_s:.0f}s after a cancel-delete")


def _delete_association(fsx, assoc_id):
    """An already-absent association is success, so this re-runs."""
    try:
        fsx.delete_data_repository_association(AssociationId=assoc_id, DeleteDataInFileSystem=False)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DataRepositoryAssociationNotFound":
            raise


def _empty_and_delete_bucket(s3, bucket):
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket,
                              Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchBucket",):
            raise


_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    """VPC/subnet/security-group delete that waits out the AWS-managed ENIs an FSx file system
    leaves behind for a bounded window, retrying DependencyViolation inside it, rather than
    stranding the network the moment a per-resource cleanup budget is hit.
    """
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return None
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


# ===== check =====

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataRepositoryAssociation validates the repository path against the real S3 bucket
    before accepting it, refusing an absent bucket; the same call against a bucket that exists
    succeeds, and only that association is ever visible on the file system.
    """
    fsx = ctx.client("fsx")
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")

    vpc, sg, azs, own = _own_network(ctx, ec2, CHECK)
    created, subnet = _create_file_system(ctx, fsx, ec2, vpc, sg, azs, own)
    fs_id = created["FileSystemId"]
    assert created["Lifecycle"] == "CREATING", (
        f"CreateFileSystem returned Lifecycle {created['Lifecycle']!r}; a file system is "
        f"provisioned asynchronously and starts CREATING")

    missing_bucket = ctx.unique_name("sim2real-behav-fsx-missing-")
    bad_code, bad_message = _error(lambda: fsx.create_data_repository_association(
        FileSystemId=fs_id, FileSystemPath="/missing", DataRepositoryPath=f"s3://{missing_bucket}",
        BatchImportMetaDataOnCreate=False))
    assert bad_code == "BadRequest", (
        f"CreateDataRepositoryAssociation against a bucket that does not exist returned "
        f"{bad_code!r}, not BadRequest")
    expected_bad_message = (
        "Amazon FSx is unable to validate the access to the S3 bucket prefix. "
        "S3 bucket does not exist.")
    assert bad_message == expected_bad_message, (
        f"expected message {expected_bad_message!r}, got {bad_message!r}")

    listed = fsx.describe_data_repository_associations(
        Filters=[{"Name": "file-system-id", "Values": [fs_id]}])["Associations"]
    assert listed == [], (
        f"the refused association still shows up on the file system: {listed!r}")

    bucket = ctx.unique_name("sim2real-behav-fsx-dra-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    repo_path = f"s3://{bucket}"
    good = fsx.create_data_repository_association(
        FileSystemId=fs_id, FileSystemPath="/data", DataRepositoryPath=repo_path,
        BatchImportMetaDataOnCreate=False, Tags=own,
    )["Association"]
    assoc_id = good["AssociationId"]
    ctx.on_cleanup(lambda: _delete_association(fsx, assoc_id))
    assert good["Lifecycle"] == "CREATING", (
        f"CreateDataRepositoryAssociation against a real bucket returned Lifecycle "
        f"{good['Lifecycle']!r}, not CREATING -- the positive control did not succeed")
    assert good["DataRepositoryPath"] == repo_path, (
        f"the accepted association reports DataRepositoryPath {good['DataRepositoryPath']!r}, "
        f"not {repo_path!r}")

    listed_after = fsx.describe_data_repository_associations(
        Filters=[{"Name": "file-system-id", "Values": [fs_id]}])["Associations"]
    assert {a["AssociationId"] for a in listed_after} == {assoc_id}, (
        f"DescribeDataRepositoryAssociations returned {[a['AssociationId'] for a in listed_after]}, "
        f"not exactly the positive control's association {assoc_id!r}")

    _delete_association(fsx, assoc_id)
    _cancel_file_system(fsx, fs_id)
    _wait_gone(fsx, fs_id)
    _empty_and_delete_bucket(s3, bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
