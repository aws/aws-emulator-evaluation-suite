"""concurrent-share-directory-race-conflict."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "concurrent-share-directory-race-conflict"
GROUP = "concurrency"
SERVICES = ["ds"]

_AZ_REJECTED_RE = re.compile(r"Availability Zone:\s*(\S+)\s+corresponding to subnet")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent ShareDirectory calls to the same target account resolve to exactly one
    success and one DirectoryAlreadySharedException, leaving one share record whose id is the
    winner's, so the owner enforces a single share per target under concurrency."""
    ds = ctx.client("ds")
    name = ctx.unique_name("sim2real-ds-sharerace").replace("_", "-").rstrip("-") + ".test"
    directory_id = _create_directory_retrying_az(ctx, ds, name)
    ctx.on_cleanup(lambda: _safe(lambda: _delete_directory_and_wait(ds, directory_id)))
    _wait_directory_active(ds, directory_id)

    # A documentation placeholder account: HANDSHAKE sharing does not check that the target exists.
    target_account_id = "111122223333"
    target = {"Id": target_account_id, "Type": "ACCOUNT"}

    def _share(_):
        try:
            resp = ds.share_directory(DirectoryId=directory_id, ShareTarget=target, ShareMethod="HANDSHAKE")
            return ("ok", resp["SharedDirectoryId"])
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"),
                    e.response["ResponseMetadata"]["RequestId"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_share, range(2)))

    ctx.on_cleanup(lambda: _safe(lambda: ds.unshare_directory(DirectoryId=directory_id, UnshareTarget=target)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly one ShareDirectory to succeed, got {results}"
    assert len(failures) == 1, f"expected exactly one ShareDirectory to fail, got {results}"
    assert failures[0][1] == "DirectoryAlreadySharedException", (
        f"expected the losing ShareDirectory to fail with DirectoryAlreadySharedException, got {failures[0][1]!r}"
    )
    assert failures[0][2] == (
        f"Directory {directory_id} is already shared with Account {target_account_id}. : "
        f"RequestId: {failures[0][3]}"
    ), f"unexpected DirectoryAlreadySharedException message: {failures[0][2]!r}"

    shares = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    matching = [s for s in shares if s["SharedAccountId"] == target_account_id]
    assert len(matching) == 1, f"expected exactly one share record for {target_account_id}, found {len(matching)}"
    assert matching[0]["SharedDirectoryId"] == successes[0][1], (
        f"the persisted share record {matching[0]['SharedDirectoryId']!r} does not match the id the "
        f"winning ShareDirectory call returned {successes[0][1]!r}"
    )


# ===== helpers =====
_GONE_CODES = (
    "EntityDoesNotExistException",
    "DirectoryDoesNotExistException",
    "DirectoryNotSharedException",
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
)


def _safe(fn) -> None:
    """Run a teardown call: a resource or share that is already gone is fine, anything else raises."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in _GONE_CODES:
            raise


def _initial_vpc_and_subnets_by_az(ctx):
    """Create-or-adopt: reuse the run's shared network when it already has subnets in
    >=2 AZs (the common case), otherwise provision a dedicated,
    tagged VPC -- a freshly provisioned account may have no shared network at all, and this
    check must not depend on one existing. Returns every AZ found (not just two), plus
    whether the VPC is ours to add more subnets to."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, by_az, False

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose two available AZs to place directory subnets")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [
                {"Key": "Name", "Value": ctx.unique_name("sim2real-ds-sharerace-vpc-")},
                {"Key": "sim2real", "Value": "ds-behavioral"},
            ],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    by_az = {}
    for i, az in enumerate(azs[:2]):
        by_az[az] = _create_tagged_subnet(ctx, ec2, vpc_id, i, az)
    return vpc_id, by_az, True


def _create_tagged_subnet(ctx, ec2, vpc_id, index, az):
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=f"10.91.{index}.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [
                {"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-sharerace-subnet{index}-")},
                {"Key": "sim2real", "Value": "ds-behavioral"},
            ],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
    ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return subnet_id


def _create_directory_retrying_az(ctx, ds, name):
    """CreateMicrosoftAD can reject one of the account's AZs as "capacity constrained"
    for Directory Service even though EC2 already has a subnet there and lists the AZ
    as available, so this retries with a different AZ pair on that specific error."""
    ec2 = ctx.client("ec2")
    vpc_id, by_az, ours_to_extend = _initial_vpc_and_subnets_by_az(ctx)
    rejected: set = set()
    while True:
        candidates = [az for az in by_az if az not in rejected]
        if len(candidates) < 2:
            if not ours_to_extend:
                raise AssertionError(
                    f"the default VPC does not have 2 AZs Directory Service accepts "
                    f"(rejected as capacity-constrained: {sorted(rejected)})"
                )
            remaining_azs = [
                az["ZoneName"]
                for az in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
                    "AvailabilityZones"
                ]
                if az["ZoneName"] not in by_az
            ]
            if not remaining_azs:
                raise AssertionError(
                    f"could not find 2 AZs Directory Service accepts in this region "
                    f"(rejected as capacity-constrained: {sorted(rejected)})"
                )
            az = remaining_azs[0]
            by_az[az] = _create_tagged_subnet(ctx, ec2, vpc_id, len(by_az), az)
            candidates = [az for az in by_az if az not in rejected]

        subnet_ids = [by_az[az] for az in candidates[:2]]
        try:
            resp = ds.create_microsoft_ad(
                Name=name,
                Password="TestPassw0rd!23",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
                Edition="Standard",
                Tags=[{"Key": "sim2real", "Value": "ds-behavioral"}, {"Key": "Name", "Value": name}],
            )
            return resp["DirectoryId"]
        except ClientError as exc:
            error = exc.response.get("Error", {})
            match = _AZ_REJECTED_RE.search(error.get("Message", ""))
            if error.get("Code") == "ClientException" and match:
                rejected.add(match.group(1))
                continue
            raise


def _wait_directory_active(ds, directory_id, timeout_s=2700.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage == "Active":
            return desc
        if last_stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach Active within {timeout_s}s (last={last_stage})")


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


def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=30.0):
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
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "DirectoryDoesNotExistException",
                        "EntityDoesNotExistException",
                    ):
                        raise
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
