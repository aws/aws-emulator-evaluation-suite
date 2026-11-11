"""shared-directory-lifecycle-transitions."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "shared-directory-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["ds"]

# A syntactically valid but fabricated account id, distinct from the caller's account:
# ShareDirectory to it succeeds and produces a PendingAcceptance record without needing
# that account to exist or cooperate.
_POSITIVE_CONTROL_TARGET_ACCOUNT = "234567890123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ShareDirectory to a distinct account yields a PendingAcceptance record, while ShareDirectory to the
    owner's own account fails with InvalidTargetException and AWS's exact message and leaves no record;
    a fresh directory starts with none."""
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    ctx.on_cleanup(lambda: _cleanup_delete_directory(ctx, directory_id))
    desc = _wait_for_directory_stage(ctx, ds, directory_id, {"Active", "Failed"}, timeout_s=2700)
    assert desc["Stage"] == "Active", f"expected directory to reach Active, got {desc['Stage']!r}: {desc.get('StageReason')}"

    baseline = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert baseline == [], f"positive control failed: fresh directory has stray shares: {baseline}"

    own_account_id = ctx.client("sts").get_caller_identity()["Account"]
    assert _POSITIVE_CONTROL_TARGET_ACCOUNT != own_account_id, "fabricated target account collides with the caller's account"

    other_target = {"Id": _POSITIVE_CONTROL_TARGET_ACCOUNT, "Type": "ACCOUNT"}
    share_resp = ds.share_directory(
        DirectoryId=directory_id,
        ShareTarget=other_target,
        ShareMethod="HANDSHAKE",
        ShareNotes="sim2real behavioral fidelity check - positive control",
    )
    ctx.on_cleanup(lambda: _cleanup_unshare(ds, directory_id, other_target))
    shared_id = share_resp["SharedDirectoryId"]
    pending = _find_share(ds, directory_id, shared_id)
    assert pending is not None, f"ShareDirectory to a distinct account produced no shared-directory record: {shared_id}"
    assert pending["ShareStatus"] == "PendingAcceptance", (
        f"expected a pending share after targeting a distinct account, got {pending['ShareStatus']!r}"
    )

    ds.unshare_directory(DirectoryId=directory_id, UnshareTarget=other_target)
    _wait_share_gone(ds, directory_id, shared_id)

    code, message, request_id = _error(
        lambda: ds.share_directory(
            DirectoryId=directory_id,
            ShareTarget={"Id": own_account_id, "Type": "ACCOUNT"},
            ShareMethod="HANDSHAKE",
            ShareNotes="sim2real behavioral fidelity check",
        )
    )
    assert code == "InvalidTargetException", f"expected InvalidTargetException for a self-share, got {code!r}"
    assert message == (
        f"The Target AWS account ID {own_account_id} you specified cannot be the same as the directory "
        f"owner AWS account ID. : RequestId: {request_id}"
    ), f"unexpected InvalidTargetException message: {message!r}"

    after = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert after == [], f"a shared-directory record was created despite the rejected self-share: {after}"


# ===== helpers =====

def _error(fn):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", ""), e.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _tag_spec(rtype: str, name: str) -> list:
    return [{
        "ResourceType": rtype,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    }]


_SHARED_VPC_TAG_NAME = "sim2real-ds-shared-vpc"


def _usable_vpc(ec2, *, ctx):
    """Any VPC already in the account with subnets across >=2 AZs -- the shared network
    first if present, else any other. Preferred over creating a fresh VPC: this
    account's VPC quota is small and shared across many concurrent runs, and creating
    one here can fail with VpcLimitExceeded even for a single attempt."""
    seen: set[str] = set()
    for filters in ([{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}],):
        vpcs = ec2.describe_vpcs(Filters=filters)["Vpcs"]
        for v in sorted(vpcs, key=lambda x: x["VpcId"]):
            if v["VpcId"] in seen or v["State"] != "available":
                continue
            seen.add(v["VpcId"])
            subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [v["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
            subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
            by_az: dict[str, str] = {}
            for s in subnets:
                if s["State"] == "available":
                    by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
            # Every distinct-AZ subnet, not just 2: CreateMicrosoftAD can reject an
            # individual AZ as capacity-constrained (see _create_microsoft_ad), and the
            # caller needs spare candidates to retry with rather than one fixed pair.
            if len(by_az) >= 2:
                return v["VpcId"], list(by_az.values())
    return None


def _get_or_create_shared_vpc(ctx):
    """Adopt any already-usable VPC first (see _usable_vpc). Only when the account has
    none at all does this look up (and, failing that, create) a tagged shared VPC, so
    concurrent checks converge on a single VPC instead of each provisioning their own.
    No single check deletes a created
    shared VPC; it persists across runs."""
    ec2 = ctx.client("ec2")

    usable = _usable_vpc(ec2, ctx=ctx)
    if usable is not None:
        return usable

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [_SHARED_VPC_TAG_NAME]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    if not vpcs:
        try:
            ec2.create_vpc(CidrBlock="10.91.0.0/16", TagSpecifications=_tag_spec("vpc", _SHARED_VPC_TAG_NAME))
        except ClientError:
            pass
        for _ in range(15):
            vpcs = _existing()
            if vpcs:
                break
            time.sleep(2)
    if not vpcs:
        raise AssertionError("no usable VPC exists and the shared sim2real-ds VPC could not be created (account may be at its VPC quota)")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs required by CreateMicrosoftAD")

    for i, az in enumerate(azs):
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.91.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=_tag_spec("subnet", f"{_SHARED_VPC_TAG_NAME}-subnet{i}"),
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                continue
            raise
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    return vpc_id, subnet_ids


_UNSUPPORTED_AZ_SUBNET_RE = re.compile(r"corresponding to subnet:\s*(subnet-[0-9a-f]+)")


def _create_microsoft_ad(ctx) -> str:
    """CreateMicrosoftAD can reject one specific AZ of a VPC as capacity-constrained for
    Directory Service ("Failed to locate Availability Zone: ... corresponding to
    subnet: ... This availability zone may be capacity constrained.") even though the
    subnet itself is healthy. The error names the offending subnet, so drop exactly that one
    and retry with the next candidate pair."""
    ds = ctx.client("ds")
    vpc_id, candidate_subnet_ids = _get_or_create_shared_vpc(ctx)
    name = ctx.unique_name("sim2realds") + ".test"

    remaining = list(candidate_subnet_ids)
    last_exc = None
    while len(remaining) >= 2:
        pair = remaining[:2]
        try:
            resp = ds.create_microsoft_ad(
                Name=name,
                Password="Sim2Real-Test-Passw0rd!",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": pair},
                Edition="Standard",
                Tags=[{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
            )
            return resp["DirectoryId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if code == "ClientException" and "Availability Zone" in msg:
                last_exc = exc
                match = _UNSUPPORTED_AZ_SUBNET_RE.search(msg)
                bad = match.group(1) if match else pair[-1]
                remaining = [s for s in remaining if s != bad]
                continue
            raise
    raise last_exc or AssertionError("fewer than 2 usable subnet candidates to try CreateMicrosoftAD with")


def _cleanup_delete_directory(ctx, directory_id: str) -> None:
    ds = ctx.client("ds")
    try:
        _delete_directory_and_wait(ds, directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _cleanup_unshare(ds, directory_id: str, target: dict) -> None:
    try:
        ds.unshare_directory(DirectoryId=directory_id, UnshareTarget=target)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("EntityDoesNotExistException", "DirectoryNotSharedException"):
            raise


def _find_share(ds, directory_id: str, shared_directory_id: str):
    shares = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    matches = [s for s in shares if s["SharedDirectoryId"] == shared_directory_id]
    return matches[0] if matches else None


def _wait_share_gone(ds, directory_id: str, shared_directory_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        share = _find_share(ds, directory_id, shared_directory_id)
        if share is None:
            return
        last_status = share["ShareStatus"]
        if last_status == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"share {shared_directory_id} still present (status={last_status!r}) after {timeout_s}s")


def _wait_for_directory_stage(ctx, ds, directory_id: str, targets: set[str], timeout_s: float = 2700.0, interval_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage in targets:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage {last_stage!r} after {timeout_s}s")


def _delete_directory_and_wait(ds, directory_id, timeout_s=1500.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""
    from botocore.exceptions import ClientError

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
                            "DirectoryDoesNotExistException",
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
