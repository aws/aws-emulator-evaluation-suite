"""concurrent-add-ip-routes-duplicate-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-add-ip-routes-duplicate-conflict"
GROUP = "concurrency"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent AddIpRoutes calls for one CIDR on an Active directory resolve to exactly one
    success and one rejection (EntityAlreadyExistsException, or ClientException while the winner's
    update is in progress), and ListIpRoutes holds exactly one entry for the CIDR."""
    ds = ctx.client("ds")
    directory_id = _create_active_microsoft_ad(ctx)
    cidr = "198.51.100.0/24"  # TEST-NET-2 (RFC 5737) -- AddIpRoutes documents public-range routing

    barrier = threading.Barrier(2)

    def _racer() -> tuple[str, str | None, str]:
        barrier.wait()
        try:
            ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr}])
            return ("ok", None, "")
        except Exception as exc:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                err = exc.response["Error"]
                return ("error", err["Code"], err.get("Message", ""))
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_racer) for _ in range(2)]
        results = [f.result(timeout=120) for f in futures]

    ctx.on_cleanup(lambda: _safe_remove_ip_route(ds, directory_id, cidr))

    oks = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]
    assert len(oks) == 1, f"expected exactly 1 success, got {len(oks)} (results={results})"
    assert len(errors) == 1, f"expected exactly 1 error, got {len(errors)} (results={results})"
    loser_code, loser_message = errors[0][1], errors[0][2]
    _busy_phrases = ("in progress", "under maintenance", "unavailable for updates")
    if loser_code == "ClientException":
        assert any(p in loser_message.lower() for p in _busy_phrases), (
            f"ClientException on the losing racer was not a directory-busy contention "
            f"error: {loser_message}"
        )
    else:
        assert loser_code == "EntityAlreadyExistsException", (
            f"unexpected error code on the losing racer: {loser_code} ({loser_message})"
        )

    status = _wait_for_ip_route_status(ctx, ds, directory_id, cidr, {"Added", "AddFailed"}, timeout_s=600.0)
    assert status == "Added", f"IP route reached terminal status {status!r} instead of Added"

    matching = [r for r in ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"] if r["CidrIp"] == cidr]
    assert len(matching) == 1, f"expected exactly 1 route entry for {cidr}, found {len(matching)}"


# ===== helpers =====


def _create_vpc_with_subnets(ctx) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-ds-")
    vpc = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:2]
    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.0.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{tag}{i}"}]}
            ],
        )
        subnet_ids.append(subnet["Subnet"]["SubnetId"])

    def _cleanup() -> None:
        for sid in subnet_ids:
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_active_microsoft_ad(ctx) -> str:
    # Simple AD (CreateDirectory) is "no longer open to new customers" on real AWS
    # (ClientException) -- create_microsoft_ad is the supported equivalent with the
    # same Creating -> Active lifecycle this check depends on.
    ds = ctx.client("ds")
    net = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password="TestPassw0rd!2345",
        Edition="Standard",
        VpcSettings={"VpcId": net["vpc_id"], "SubnetIds": net["subnet_ids"]},
    )
    directory_id = resp["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ds, directory_id))
    stage = _wait_for_directory_stage(ctx, ds, directory_id, {"Active", "Failed", "Impaired"}, timeout_s=3600.0)
    if stage != "Active":
        raise AssertionError(f"prerequisite directory did not reach Active (got {stage!r})")
    return directory_id


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_directory_stage(ctx, ds, directory_id: str, target_stages: set[str], timeout_s: float) -> str | None:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            return None
        last_stage = descs[0]["Stage"]
        if last_stage in target_stages:
            return last_stage
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"directory {directory_id} reaching {target_stages}: the run budget ended first; not graded")
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s:.0f}s, last stage={last_stage}"
    )


def _wait_for_ip_route_status(
    ctx, ds, directory_id: str, cidr: str, target_statuses: set[str], timeout_s: float
) -> str | None:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        matching = [r for r in routes if r["CidrIp"] == cidr]
        if matching:
            last_status = matching[0]["IpRouteStatusMsg"]
            if last_status in target_statuses:
                return last_status
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"IP route {cidr} reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(
        f"IP route {cidr} did not reach {target_statuses} within {timeout_s:.0f}s, last status={last_status}"
    )


def _safe_remove_ip_route(ds, directory_id: str, cidr: str) -> None:
    try:
        ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _safe_delete_directory(ds, directory_id: str) -> None:
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise
        return
    deadline = time.monotonic() + 1140.0  # with the 630 s network teardown, fits the 1800 s budget
    while time.monotonic() < deadline:
        try:
            resp = ds.describe_directories(DirectoryIds=[directory_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise
            return
        descs = resp.get("DirectoryDescriptions", [])
        if not descs or descs[0]["Stage"] == "Deleted":
            return
        time.sleep(2.0)
    raise AssertionError(f"directory {directory_id} still exists 1140s after DeleteDirectory")


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
