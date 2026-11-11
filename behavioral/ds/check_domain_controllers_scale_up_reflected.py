"""domain-controllers-scale-up-reflected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Directory Service cannot place domain controllers in these zones (CreateMicrosoftAD: "Failed to
# locate Availability Zone: us-west-2d"); subnets there are never offered to it.
_DS_UNSUPPORTED_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

CHECK = "domain-controllers-scale-up-reflected"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNumberOfDomainControllers on a Managed Microsoft AD directory increases
    the domain controller count, and DescribeDomainControllers eventually lists the
    new topology (one new entry per added controller)."""
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    ctx.on_cleanup(lambda: _cleanup_delete_directory(ctx, directory_id))
    desc = _wait_for_directory_stage(ctx, ds, directory_id, {"Active", "Failed"}, timeout_s=2700)
    assert desc["Stage"] == "Active", f"directory {directory_id} reached {desc['Stage']!r} instead of Active: {desc.get('StageReason')}"

    baseline = ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"]
    baseline_count = len(baseline)
    assert baseline_count == 2, f"expected the default 2 domain controllers, found {baseline_count}"

    target_count = baseline_count + 1
    ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=target_count)

    def _cleanup_scale_down():
        try:
            ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=baseline_count)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup_scale_down)

    final = _wait_for_dc_count(ctx, ds, directory_id, target_count, timeout_s=2700)
    assert len(final) == target_count, f"expected {target_count} domain controllers, found {len(final)}"


def _default_vpc_azs(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to host the directory's network interfaces")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s["AvailabilityZone"] not in _DS_UNSUPPORTED_AZS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in >=2 availability zones, required by CreateMicrosoftAD")
    return vpc_id, by_az


def _create_microsoft_ad(ctx) -> str:
    ds = ctx.client("ds")
    vpc_id, by_az = _default_vpc_azs(ctx)
    name = ctx.unique_name("sim2realds") + ".test"
    last_exc: ClientError | None = None
    # AWS documents that Managed Microsoft AD does not support every Availability Zone in a
    # region (some are capacity-constrained); which AZ that is varies per account since AZ
    # letters are a per-account alias for a physical zone. Try every distinct pair from the
    # default VPC rather than assuming the first two are usable.
    for subnet_ids in itertools.combinations(by_az.values(), 2):
        try:
            resp = ds.create_microsoft_ad(
                Name=name,
                Password="Sim2Real-Test-Passw0rd!",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(subnet_ids)},
                Edition="Standard",
                Tags=[{"Key": "sim2real", "Value": "behavioral"},
                      {"Key": "sim2real-check", "Value": CHECK}],
            )
            return resp["DirectoryId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "ClientException" and "Availability Zone" in message:
                last_exc = exc
                continue
            raise
    raise AssertionError(
        f"no pair among the default VPC's {len(by_az)} availability zone(s) is usable by "
        f"CreateMicrosoftAD; last error: {last_exc}"
    )


def _cleanup_delete_directory(ctx, directory_id: str) -> None:
    ds = ctx.client("ds")
    try:
        _delete_directory_and_wait(ds, directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


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


def _wait_for_dc_count(ctx, ds, directory_id: str, target_count: int, timeout_s: float = 2700.0, interval_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        last = ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"]
        if len(last) >= target_count:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain controller count stuck at {len(last)}, expected {target_count}, after {timeout_s}s")



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
