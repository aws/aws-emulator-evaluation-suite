"""accept-shared-directory-nonexistent-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "accept-shared-directory-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["ds"]

_BOGUS_SHARED_DIRECTORY_ID = "d-9026a1b2c3"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptSharedDirectory on a SharedDirectoryId no handshake created fails with EntityDoesNotExistException
    "Directory: '<id>' does not exist." and creates no shared-directory record, while tagging the same
    directory succeeds, so the rejection is specific to the missing share."""
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    ctx.on_cleanup(lambda: _cleanup_delete_directory(ctx, directory_id))
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    control_key = ctx.unique_name("sim2real-control-")
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": control_key, "Value": "ok"}])
    control_tags = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    assert any(t["Key"] == control_key and t["Value"] == "ok" for t in control_tags), (
        f"positive control failed: tagging a real, healthy directory should succeed and round-trip, got {control_tags!r}"
    )

    baseline = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert baseline == [], "positive control failed: a fresh directory should have no shared-directory records"

    code, message, request_id = _error(
        lambda: ds.accept_shared_directory(SharedDirectoryId=_BOGUS_SHARED_DIRECTORY_ID)
    )
    assert code == "EntityDoesNotExistException", f"expected EntityDoesNotExistException, got {code!r}"
    assert message == (
        f"Directory: '{_BOGUS_SHARED_DIRECTORY_ID}' does not exist. : RequestId: {request_id}"
    ), f"unexpected EntityDoesNotExistException message: {message!r}"

    after = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert after == [], f"a shared-directory record appeared despite the rejected accept: {after}"


# ===== helpers =====

def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId). Raises if the call succeeded."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message"), request_id
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network in this account/region to host the directory's network interfaces")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in >=2 availability zones, required by CreateDirectory")
    subnet_ids = [by_az[az] for az in sorted(by_az)[:2]]
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx) -> str:
    # Simple AD is closed to new customers (CreateDirectory returns ClientException), so the
    # owned directory is AWS Managed Microsoft AD; the rejection does not depend on its type.
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    name = ctx.unique_name("sim2realds") + ".test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password="Sim2Real-Test-Passw0rd!",
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )
    return resp["DirectoryId"]


def _wait_for_directory_stage(ctx, directory_id: str, target_stages: set[str], timeout_s: float = 2700, interval_s: float = 30) -> str:
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"]
        if last in target_stages:
            return last
        if last in {"Failed", "Inoperable"} and last not in target_stages:
            raise AssertionError(f"directory {directory_id} reached unexpected stage {last}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={last})")


def _cleanup_delete_directory(ctx, directory_id: str) -> None:
    ds = ctx.client("ds")
    deadline = time.monotonic() + 1740  # fits the suite's 1800 s cleanup budget
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        if desc["Stage"] in {"Active", "Failed"}:
            break
        time.sleep(2)
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
