"""add-ip-routes-overlapping-cidr-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "add-ip-routes-overlapping-cidr-rejected"
GROUP = "overly-permissive"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!Test2024"


@tags(
    "axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes",
    "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """AddIpRoutes for a CIDR already on the directory fails with ClientException and its exact "already
    exist" message (not the documented EntityAlreadyExistsException) and keeps one Added route, while a
    new CIDR on the same directory succeeds."""
    ds = ctx.client("ds")
    directory_id, _ = _create_simple_ad(ctx)

    cidr = "203.0.113.0/24"
    ds.add_ip_routes(
        DirectoryId=directory_id,
        IpRoutes=[{"CidrIp": cidr, "Description": "sim2real-initial"}],
    )
    _wait_ip_route_status(ctx, directory_id, cidr, {"Added"})

    # The directory can still be applying the first route after it reads Added; AWS then
    # answers "An update is already in progress", so the duplicate add waits that out.
    busy = f"An update is already in progress for directory {directory_id}."
    deadline = time.monotonic() + min(600.0, ctx.time_left())
    while True:
        error, request_id = _error(
            lambda: ds.add_ip_routes(
                DirectoryId=directory_id,
                IpRoutes=[{"CidrIp": cidr, "Description": "sim2real-dup"}],
            )
        )
        if not (error.get("Message") or "").startswith(busy) or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert error.get("Code") == "ClientException", f"unexpected error: {error}"
    expected_message = (
        f"The IP route(s) [{cidr}] already exist. If you want to recreate them, please delete "
        f"the existing routes first. : RequestId: {request_id}"
    )
    assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error}"

    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matching = [r for r in routes if r["CidrIp"] == cidr]
    assert len(matching) == 1, "the rejected duplicate must not create a second route entry"
    assert matching[0]["IpRouteStatusMsg"] == "Added", (
        "the existing route's status must be unaffected by the rejected duplicate add"
    )

    # Positive control: a genuinely new, non-overlapping CIDR still succeeds.
    other_cidr = "198.51.100.0/24"
    ds.add_ip_routes(
        DirectoryId=directory_id,
        IpRoutes=[{"CidrIp": other_cidr, "Description": "sim2real-control"}],
    )
    _wait_ip_route_status(ctx, directory_id, other_cidr, {"Added"})


def _error(fn):
    """Return (Error dict, RequestId) of the ClientError fn() raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}), (exc.response.get("ResponseMetadata") or {}).get("RequestId")
    raise AssertionError(f"expected the call to be rejected but it succeeded: {result!r}")


def _pick_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for sn in subnets:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
        if len(by_az) >= 2:
            # The lowest-lettered zones: Directory Service refuses a subnet in some zones
            # (for example the fourth zone of us-west-2), and describe order is arbitrary.
            return vpc["VpcId"], [by_az[zone] for zone in sorted(by_az)][:2]
    raise AssertionError("no VPC with subnets in >=2 availability zones to provision a DS directory")


def _wait_directory_stage(ctx, directory_id, target_stages, timeout_s=2700, interval_s=20):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory entered terminal failure stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(f"directory did not reach {target_stages} within {timeout_s}s (last={stage})")


def _create_simple_ad(ctx, name_prefix="sim2realds"):
    # NOTE: Simple AD (via create_directory) is "no longer open to new customers" on real
    # AWS; create_microsoft_ad is the supported equivalent that still yields a directory
    # with the same Creating -> Active lifecycle used by this check.
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _pick_vpc_and_subnets(ctx)
    name = f"{ctx.unique_name(name_prefix)}.test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "sim2real", "Value": "true"}, {"Key": "sim2real:managed", "Value": "true"}],
    )["DirectoryId"]

    def _cleanup():
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _wait_directory_stage(ctx, directory_id, {"Active"})
    return directory_id, name


def _wait_ip_route_status(ctx, directory_id, cidr, target_statuses, timeout_s=300, interval_s=5):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        for r in routes:
            if r["CidrIp"] == cidr:
                status = r["IpRouteStatusMsg"]
                if status in target_statuses:
                    return r
                if status.endswith("Failed"):
                    raise AssertionError(f"IP route {cidr} failed with status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"IP route {cidr} never reached {target_statuses} (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
