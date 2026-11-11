"""concurrent-add-ip-routes-conflict-detected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-add-ip-routes-conflict-detected"
GROUP = "concurrency"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent AddIpRoutes calls for the same CIDR on a Managed Microsoft AD leave one
    persisted route; the loser gets ClientException with the directory-update-in-progress lock
    message, or the route-already-exists message when it lands after the winner's update completes.
    """
    directory_id = _create_microsoft_ad(ctx)
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=_budget_s(ctx, 2700))

    ds = ctx.client("ds")
    cidr = "198.51.100.0/24"

    def _racer():
        try:
            ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr}])
            return None
        except ClientError as e:
            return {**e.response["Error"], "RequestId": e.response["ResponseMetadata"]["RequestId"]}

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _racer(), range(2)))

    winners = [r for r in results if r is None]
    losers = [r for r in results if r is not None]
    assert len(winners) == 1, f"expected exactly 1 winner, got {len(winners)} (results={results})"
    assert len(losers) == 1, f"expected exactly 1 loser, got {len(losers)} (results={results})"
    loser = losers[0]
    assert loser.get("Code") == "ClientException", f"unexpected loser error code {loser!r}"
    lock_message = (
        f"An update is already in progress for directory {directory_id}. Please wait until "
        f"this update is complete before making another change. : RequestId: {loser['RequestId']}"
    )
    exists_message = (
        f"The IP route(s) [{cidr}] already exist. If you want to recreate them, please delete "
        f"the existing routes first. : RequestId: {loser['RequestId']}"
    )
    expected_message = exists_message if loser.get("Message") == exists_message else lock_message
    assert loser.get("Message") == expected_message, (
        f"loser was ClientException but neither the update-lock nor the route-exists rejection: {loser!r}"
    )

    ctx.on_cleanup(lambda: _safe_remove_route(ctx, directory_id, cidr))

    _wait_for_route_status(ctx, directory_id, cidr, {"Added"}, timeout_s=_budget_s(ctx, 180))
    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matching = [r for r in routes if r["CidrIp"] == cidr]
    assert len(matching) == 1, f"expected exactly 1 persisted route for {cidr}, found {len(matching)}"


# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


def _network_two_azs(ctx):
    """The shared network's VPC and its subnets in the first two zones Directory Service supports."""
    net = ctx.network()
    zone_ids = {
        z["ZoneName"]: z["ZoneId"]
        for z in ctx.client("ec2").describe_availability_zones(ZoneNames=net.availability_zones)[
            "AvailabilityZones"
        ]
    }
    azs = [az for az in net.availability_zones if zone_ids.get(az) not in _DS_UNSUPPORTED_ZONE_IDS]
    if len(azs) < 2:
        raise AssertionError(f"shared network lacks two Directory Service zones: {net.subnets!r}")
    return net.vpc_id, [net.subnets[az] for az in azs[:2]]


def _create_microsoft_ad(ctx, password="Sim2Real-TestPW1"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _network_two_azs(ctx)
    name = ctx.unique_name("sim2real-ds-") + ".test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        ShortName="SIM2REAL",
        Password=password,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ctx, directory_id))
    return directory_id


def _safe_delete_directory(ctx, directory_id):
    ds = ctx.client("ds")
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _safe_remove_route(ctx, directory_id, cidr):
    ds = ctx.client("ds")
    try:
        ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _directory_stage(ctx, directory_id):
    ds = ctx.client("ds")
    resp = ds.describe_directories(DirectoryIds=[directory_id])
    descs = resp["DirectoryDescriptions"]
    return descs[0]["Stage"] if descs else None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=2700, interval_s=2):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _directory_stage(ctx, directory_id)
        if last in target_stages:
            return last
        if last in ("Failed", "Impaired", "Inoperable") and last not in target_stages:
            raise AssertionError(f"directory {directory_id} reached unexpected stage {last}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"directory {directory_id} reaching {target_stages}: the run budget ended first; not graded")
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={last})"
    )


def _wait_for_route_status(ctx, directory_id, cidr, target_statuses, timeout_s=180, interval_s=2):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        matching = [r for r in routes if r["CidrIp"] == cidr]
        last = matching[0]["IpRouteStatusMsg"] if matching else None
        if last in target_statuses:
            return last
        if last == "AddFailed" and "AddFailed" not in target_statuses:
            raise AssertionError(f"route {cidr} failed to add")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"route {cidr} reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"route {cidr} did not reach {target_statuses} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
