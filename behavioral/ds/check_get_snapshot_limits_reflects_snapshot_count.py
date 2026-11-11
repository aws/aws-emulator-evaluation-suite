"""get-snapshot-limits-reflects-snapshot-count."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Directory Service cannot place domain controllers in these zones (CreateMicrosoftAD: "Failed to
# locate Availability Zone: us-west-2d"), so subnets there are never offered to it.
_DS_UNSUPPORTED_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

CHECK = "get-snapshot-limits-reflects-snapshot-count"
GROUP = "data-plane"
SERVICES = ["ds"]

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_MAD_NAME = "sim2dssnaplim.sim2real.test"
_SHARED_MAD_VPC_TAG = "sim2real-ds-snaplim-vpc"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSnapshotLimits.ManualSnapshotsCurrentCount rises by one after CreateSnapshot and returns to
    baseline after DeleteSnapshot; DescribeSnapshots on the deleted id is InvalidParameterException.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/API_GetSnapshotLimits.html"""
    ds = ctx.client("ds")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    # The directory is shared, so the baseline is read, not assumed 0. Auto snapshots do not count
    # toward ManualSnapshotsCurrentCount and cannot be deleted; only a Manual one can be a leftover.
    existing = [
        s for s in ds.describe_snapshots(DirectoryId=directory_id)["Snapshots"]
        if s["Status"] != "Failed" and s.get("Type") == "Manual"
    ]
    if existing:
        # Left by an earlier run that timed out before DeleteSnapshot; prove the decrement half.
        snapshot_id = existing[0]["SnapshotId"]
        baseline = _current_count(ds, directory_id) - 1
    else:
        baseline = _current_count(ds, directory_id)
        snapshot_id = _retry_directory_busy(
            lambda: ds.create_snapshot(DirectoryId=directory_id)["SnapshotId"]
        )

        def _incremented():
            return _current_count(ds, directory_id) == baseline + 1

        assert _poll_until(_incremented, timeout_s=60, interval_s=5), (
            f"ManualSnapshotsCurrentCount never incremented after CreateSnapshot "
            f"(baseline={baseline}, now={_current_count(ds, directory_id)})"
        )

    ctx.on_cleanup(lambda: _safe(lambda: ds.delete_snapshot(SnapshotId=snapshot_id)))

    _delete_snapshot_with_retry(ds, snapshot_id, timeout_s=1800, interval_s=10)

    def _decremented():
        return _current_count(ds, directory_id) == baseline

    assert _poll_until(_decremented, timeout_s=60, interval_s=5), (
        f"ManualSnapshotsCurrentCount never returned to baseline after DeleteSnapshot "
        f"(baseline={baseline}, now={_current_count(ds, directory_id)})"
    )

    # A deleted snapshot id gets InvalidParameterException, not EntityDoesNotExistException.
    code = _error_code(lambda: ds.describe_snapshots(SnapshotIds=[snapshot_id]))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for deleted snapshot {snapshot_id}, got {code!r}"
    )

    listed_ids = [
        s["SnapshotId"] for s in ds.describe_snapshots(DirectoryId=directory_id)["Snapshots"]
    ]
    assert snapshot_id not in listed_ids, (
        f"deleted snapshot {snapshot_id} still present in DescribeSnapshots for directory "
        f"{directory_id}: {listed_ids}"
    )


def _error_code(fn) -> str | None:
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _current_count(ds, directory_id) -> int:
    return ds.get_snapshot_limits(DirectoryId=directory_id)["SnapshotLimits"]["ManualSnapshotsCurrentCount"]


def _delete_snapshot_with_retry(ds, snapshot_id, *, timeout_s: float, interval_s: float) -> None:
    """DeleteSnapshot can reject a snapshot that's still Creating (ClientException); retry
    with backoff within budget rather than waiting the full snapshot-creation time up front."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ds.delete_snapshot(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "EntityDoesNotExistException":
                return
            if code in ("ClientException", "DirectoryUnavailableException", "ServiceException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"DeleteSnapshot never succeeded for {snapshot_id} within {timeout_s}s "
        f"(snapshot likely still Creating; re-run to let it finish): {last_exc}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _simplead_password() -> str:
    return "Sim2Real!Passw0rd123"


def _mad_password() -> str:
    return "Sim2Real-Behav!9Qx"


def _retry_directory_busy(fn, attempts: int = 10, delay_s: float = 12.0):
    """Retry a mutating call on the shared directory that transiently fails with
    DirectoryUnavailableException (another mutation still settling) or ServiceException."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("DirectoryUnavailableException", "ServiceException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _poll_until(predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


def _find_directory_id_by_name(ctx, name):
    ds = ctx.client("ds")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = ds.describe_directories(**kwargs)
        for desc in resp.get("DirectoryDescriptions", []):
            if desc.get("Name") == name and desc.get("Stage") not in ("Deleting", "Deleted"):
                return desc["DirectoryId"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


def _default_vpc_subnets(ctx):
    """Subnets of the shared network (DNS-enabled, one per AZ), avoiding a dedicated VPC."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s["AvailabilityZone"] not in _DS_UNSUPPORTED_AZS), key=lambda s: s["AvailabilityZone"])
    by_az = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        return None
    return vpc_id, subnet_ids


def _get_or_create_shared_vpc(ctx, tag_name, cidr_base):
    default = _default_vpc_subnets(ctx)
    if default is not None:
        return default

    ec2 = ctx.client("ec2")

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [tag_name]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    if not vpcs:
        try:
            created_vpc_id = ec2.create_vpc(
                CidrBlock=f"{cidr_base}.0.0/16",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": tag_name},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Vpc"]["VpcId"]
            ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=created_vpc_id))
        except ClientError:
            pass
        for _ in range(15):
            vpcs = _existing()
            if vpcs:
                break
            time.sleep(2)
    if not vpcs:
        raise AssertionError(f"failed to create or find the shared VPC {tag_name}")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids[:2]

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    for i, az in enumerate(azs):
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"{cidr_base}.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": f"{tag_name}-subnet{i}"},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                continue
            raise
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    return vpc_id, subnet_ids[:2]


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, *, timeout_s=2700.0, interval_s=10.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            raise AssertionError(f"directory {directory_id} vanished from DescribeDirectories while waiting")
        desc = descs[0]
        last_stage = desc["Stage"]
        if last_stage in terminal_ok:
            return desc
        if last_stage in terminal_bad:
            raise AssertionError(f"directory {directory_id} reached {last_stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(
        f"shared directory {directory_id} still at stage={last_stage} after {timeout_s}s "
        "(AWS Managed Microsoft AD provisioning genuinely takes ~20-45 minutes; background "
        "provisioning continues regardless -- re-running validate_behavioral once it completes "
        "will find it Active immediately)"
    )


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx, _SHARED_MAD_VPC_TAG, "10.80")
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_mad_password(),
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is None:
                    raise
            else:
                raise
    # The name is unique to this check, so the directory is this run's to remove, whether it was
    # created here or is a leftover of an earlier run of this check.
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ctx.client("ds"), directory_id))
    return _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"})["DirectoryId"]


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so a network
# delete waits (bounded, within the cleanup budget) for them and retries DependencyViolation, then
# raises naming the ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
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
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
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
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    network. DeleteDirectory is retried while the directory is still being created or is still
    shared with another account. Teardown-only: run() never calls this."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if "shared" in e.response["Error"].get("Message", "").lower():
                try:
                    shared = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
                except ClientError:
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in (
                            "DirectoryNotSharedException",
                            "EntityDoesNotExistException",
                        ):
                            raise
            elif code not in ("ClientException", "InvalidParameterException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(interval_s)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
