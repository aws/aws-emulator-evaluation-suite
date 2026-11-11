"""concurrent-tag-updates-converge."""
from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "concurrent-tag-updates-converge"
GROUP = "concurrency"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AddTagsToResource calls with disjoint keys on one Active directory both
    succeed and ListTagsForResource shows every tag from both, so no update is lost."""
    ds = ctx.client("ds")
    net = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    directory_id = _create_microsoft_ad_trying_subnet_pairs(ds, name, net["vpc_id"], net["subnet_ids"])
    ctx.on_cleanup(lambda: _safe_delete_directory(ds, directory_id))

    stage = _wait_for_active(ds, directory_id, timeout_s=3600.0)
    assert stage == "Active", (
        f"the directory must reach Stage 'Active' before AddTagsToResource is meaningful, "
        f"got {stage!r}"
    )

    group_a = {f"sim2real-a-{i}": f"vala-{i}" for i in range(5)}
    group_b = {f"sim2real-b-{i}": f"valb-{i}" for i in range(5)}

    barrier = threading.Barrier(2)

    def _tag(group: dict[str, str]) -> None:
        barrier.wait()
        ds.add_tags_to_resource(
            ResourceId=directory_id, Tags=[{"Key": k, "Value": v} for k, v in group.items()]
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_tag, group_a), pool.submit(_tag, group_b)]
        for f in futures:
            f.result(timeout=60)

    tags = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    expected = {**group_a, **group_b}
    for key, value in expected.items():
        assert tag_map.get(key) == value, f"tag {key!r} missing or wrong after concurrent writes: {tag_map}"


# ===== helpers =====


def _default_vpc_subnets(ec2, *, ctx) -> tuple[str, list[str]] | None:
    """The run's shared network and two of its available subnets in distinct AZs, or None.

    Preferred over a dedicated VPC, which counts against the account's VPC quota and owns
    subnets a lingering directory ENI can block from deletion."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in sorted(subnets, key=lambda x: x["SubnetId"]):
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        return None
    return vpc_id, subnet_ids


def _create_vpc_with_subnets(ctx) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    default = _default_vpc_subnets(ec2, ctx=ctx)
    if default is not None:
        vpc_id, subnet_ids = default
        return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}

    tag = ctx.unique_name("sim2real-ds-")
    vpc = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:3]
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


_UNSUPPORTED_AZ_SUBNET_RE = re.compile(r"corresponding to subnet: (subnet-[0-9a-f]+)")


def _create_microsoft_ad_trying_subnet_pairs(ds, name: str, vpc_id: str, subnet_ids: list[str]) -> str:
    """CreateMicrosoftAD can reject one AZ of a VPC as capacity-constrained for Directory
    Service ("Failed to locate Availability Zone: ... corresponding to subnet: ..."). The
    error names the subnet, so drop exactly that one and retry with the next pair."""
    remaining = list(subnet_ids)
    last_exc = None
    while len(remaining) >= 2:
        pair = remaining[:2]
        try:
            return ds.create_microsoft_ad(
                Name=name,
                Password="TestPassw0rd!2345",
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": pair},
                # A creation-time tag, independent of the concurrent AddTagsToResource calls, so
                # a tag search can still find this directory by CHECK id if those never land.
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )["DirectoryId"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ClientException" and "Availability Zone" in err.get("Message", ""):
                last_exc = exc
                match = _UNSUPPORTED_AZ_SUBNET_RE.search(err.get("Message", ""))
                bad = match.group(1) if match else pair[-1]
                remaining = [s for s in remaining if s != bad]
                continue
            raise
    raise last_exc or AssertionError(f"fewer than two candidate subnets in {vpc_id}: {subnet_ids!r}")


def _wait_for_active(ds, directory_id: str, *, timeout_s: float, interval_s: float = 30.0) -> str | None:
    """Poll DescribeDirectories until Stage leaves {Requested, Creating}, or the deadline passes:
    a Managed Microsoft AD spends tens of minutes in Creating, and AddTagsToResource fails while
    it does."""
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions") or []
        if not descs:
            return None
        stage = descs[0]["Stage"]
        if stage not in ("Requested", "Creating"):
            return stage
        time.sleep(interval_s)
    return stage


def _safe_delete_directory(ds, directory_id: str) -> None:
    # A directory still Creating refuses DeleteDirectory with ClientException, retried every 2 s;
    # with the 630 s network teardown the whole wait fits the 1800 s cleanup budget.
    deadline = time.monotonic() + 1140.0
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("DirectoryDoesNotExistException", "EntityDoesNotExistException"):
                return
            if code != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)
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
        time.sleep(30.0)
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
