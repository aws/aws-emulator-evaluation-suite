"""accept-shared-directory-already-shared-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "accept-shared-directory-already-shared-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second HANDSHAKE ShareDirectory to an account already shared with fails with
    DirectoryAlreadySharedException "Directory <id> is already shared with Account <id>." and keeps one
    shared-directory record; after UnshareDirectory, the same share succeeds again."""
    ds = ctx.client("ds")
    directory_id, _vpc_id, _subnet_ids = _create_active_microsoft_ad(ctx)
    target_account = _dummy_target_account_id(ctx, salt=1)
    target = {"Id": target_account, "Type": "ACCOUNT"}

    # Positive control: first HANDSHAKE share to this target succeeds.
    shared_directory_id = ds.share_directory(
        DirectoryId=directory_id,
        ShareMethod="HANDSHAKE",
        ShareNotes="sim2real behavioral check",
        ShareTarget=target,
    )["SharedDirectoryId"]
    ctx.on_cleanup(lambda: _best_effort_unshare(ds, directory_id, target))

    before = _shared_entries(ds, directory_id, target_account)
    assert len(before) == 1 and before[0]["SharedDirectoryId"] == shared_directory_id, (
        f"expected exactly 1 shared-directory record for {target_account} matching "
        f"{shared_directory_id!r} after the positive-control share, found {before!r}"
    )

    # Negative: re-sharing with the same already-shared target is rejected.
    code, message, request_id = _error_code(
        lambda: ds.share_directory(
            DirectoryId=directory_id,
            ShareMethod="HANDSHAKE",
            ShareTarget=target,
        )
    )
    assert code == "DirectoryAlreadySharedException", f"unexpected code: {code}"
    expected = (
        f"Directory {directory_id} is already shared with Account {target_account}. : RequestId: {request_id}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: still exactly one shared-directory record for this target.
    after = _shared_entries(ds, directory_id, target_account)
    assert len(after) == 1 and after[0]["SharedDirectoryId"] == shared_directory_id, (
        f"the rejected duplicate ShareDirectory call must leave exactly the original record in "
        f"place for {target_account}, found {after!r}"
    )

    # Restore: undo the specific state that caused the rejection (unshare the target), then
    # assert the identical ShareDirectory call now succeeds — proving the rejection tracked
    # "already shared with this target", not a general block on the operation.
    ds.unshare_directory(DirectoryId=directory_id, UnshareTarget=target)
    _wait_until_unshared(ds, directory_id, target_account)

    restored_shared_directory_id = ds.share_directory(
        DirectoryId=directory_id,
        ShareMethod="HANDSHAKE",
        ShareTarget=target,
    )["SharedDirectoryId"]
    restored = _shared_entries(ds, directory_id, target_account)
    assert len(restored) == 1 and restored[0]["SharedDirectoryId"] == restored_shared_directory_id, (
        f"re-sharing with {target_account} after unsharing must succeed and produce exactly one "
        f"shared-directory record, found {restored!r}"
    )


# ===== helpers =====


def _error_code(fn):
    """Call fn(); return its botocore (code, message, RequestId). An unexpected success raises, so a
    target that accepts a call AWS refuses is reported as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        request_id = (e.response.get("ResponseMetadata") or {}).get("RequestId")
        return e.response["Error"]["Code"], e.response["Error"].get("Message", ""), request_id
    raise AssertionError(f"expected DirectoryAlreadySharedException but the call SUCCEEDED: {result!r}")


def _wait_until_unshared(ds, directory_id, target_account, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _shared_entries(ds, directory_id, target_account)
        if not last:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"UnshareDirectory did not remove the shared-directory record for {target_account} "
        f"within {timeout_s}s; last={last!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=3600.0, interval_s=20.0):
    ds = ctx.client("ds")

    def probe():
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        return descs[0]["Stage"] if descs else None

    return _poll_until(probe, lambda s: s in target_stages, timeout_s=timeout_s, interval_s=interval_s)


def _dummy_target_account_id(ctx, salt=0):
    sts = ctx.client("sts")
    real = sts.get_caller_identity()["Account"]
    digits = list(real)
    idx = salt % len(digits)
    digits[idx] = str((int(digits[idx]) + 1 + salt) % 10)
    return "".join(digits)


def _shared_entries(ds, directory_id, target_account):
    resp = ds.describe_shared_directories(OwnerDirectoryId=directory_id)
    return [s for s in resp.get("SharedDirectories", []) if s.get("SharedAccountId") == target_account]


def _best_effort_unshare(ds, directory_id, target):
    try:
        ds.unshare_directory(DirectoryId=directory_id, UnshareTarget=target)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.61.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    if len(azs) < 2:
        raise AssertionError("region has fewer than 2 availability zones; cannot satisfy the "
                            "AWS Managed Microsoft AD 2-subnet requirement")
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.61.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{name}-{i}"}]}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s))
    return vpc_id, subnet_ids


def _create_active_microsoft_ad(ctx, edition="Standard"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password="Sim2Real-Passw0rd!23",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition=edition,
        Description="sim2real behavioral check",
        Tags=[{"Key": "Name", "Value": name}],
    )
    directory_id = resp["DirectoryId"]

    def _cleanup():
        try:
            # Bounded so this wait, the delete retry and the 630 s network teardown fit the 1800 s
            # cleanup budget.
            _wait_for_directory_stage(ctx, directory_id, {"Active", "Failed", "Impaired"}, timeout_s=840, interval_s=2)
        except AssertionError:
            pass
        # UnshareDirectory is asynchronous: DeleteDirectory is refused while the share is still
        # being removed, so retry that refusal every 2 s for up to 300 s.
        deadline = time.monotonic() + 300.0
        while True:
            try:
                ds.delete_directory(DirectoryId=directory_id)
                return
            except ClientError as e:
                if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                    return
                if "shared" not in e.response["Error"].get("Message", "").lower() \
                        or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=3600, interval_s=20)
    return directory_id, vpc_id, subnet_ids


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
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
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
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
        _time.sleep(2)


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
