"""update-domain-controllers-limit-enforced."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "update-domain-controllers-limit-enforced"
GROUP = "concurrency"
SERVICES = ["ds"]

_DS_PASSWORD = "Sim2Real-Test-Pwd-1!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateNumberOfDomainControllers above the account's discovered per-directory quota is refused
    DomainControllerLimitExceededException for each of three concurrent callers, leaving the count
    unchanged, while a within-limit request succeeds and adds a controller."""
    _ds_slow_gate(ctx)

    ds = ctx.client("ds")
    max_domain_controllers = _discover_domain_controller_limit(ctx)
    # This run's teardown clock, started by the first teardown that runs.
    clock: dict = {}
    vpc_id, az_subnet_ids = _create_vpc_for_directory(ctx, clock)
    directory_id = _create_microsoft_ad(ctx, vpc_id, az_subnet_ids, clock)
    _wait_for_stage(ctx, directory_id, {"Active"}, timeout_s=2700.0, interval_s=30.0)

    original_count = len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"])
    assert original_count >= 2

    over_limit = max_domain_controllers + 5

    def _attempt():
        try:
            result = ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=over_limit)
        except ClientError as e:
            return e.response["Error"]["Code"]
        raise AssertionError(f"DesiredNumber={over_limit} above the limit was accepted: {result!r}")

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: _attempt(), range(3)))

    assert results == ["DomainControllerLimitExceededException"] * 3, (
        f"expected every concurrent over-limit request to be rejected identically, got {results}"
    )

    # effect absent: the directory's domain controller count did not change
    unchanged_count = len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"])
    assert unchanged_count == original_count, (
        f"domain controller count changed from {original_count} to {unchanged_count} despite rejected requests"
    )

    # positive control: a within-limit request succeeds and eventually adds a controller
    target_count = original_count + 1
    ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=target_count)
    # Per AWS docs, new domain controllers may take up to 45 minutes to become fully active;
    # poll for the observable condition rather than sleeping a fixed duration.
    _wait_for_domain_controller_count(ctx, directory_id, target_count, timeout_s=2700.0, interval_s=30.0)


# ===== helpers =====


def _discover_domain_controller_limit(ctx) -> int:
    """Look up the account's current domain-controllers-per-directory quota via Service
    Quotas -- this limit is adjustable, so a hardcoded default would be a fidelity
    inversion (and a flake) against an account that has requested an increase."""
    sq = ctx.client("service-quotas")
    try:
        paginator = sq.get_paginator("list_service_quotas")
        for page in paginator.paginate(ServiceCode="ds"):
            for quota in page.get("Quotas", []):
                if "domain controller" in quota.get("QuotaName", "").lower():
                    return int(quota["Value"])
        paginator = sq.get_paginator("list_aws_default_service_quotas")
        for page in paginator.paginate(ServiceCode="ds"):
            for quota in page.get("Quotas", []):
                if "domain controller" in quota.get("QuotaName", "").lower():
                    return int(quota["Value"])
    except ClientError as err:
        raise AssertionError(
            "Service Quotas lookup for ds failed "
            f"({err.response['Error']['Code']}); cannot discover the domain "
            "controller limit without guessing a value that could be wrong for "
            "the caller's account"
        ) from err
    raise AssertionError(
        "Service Quotas does not list a 'domain controller' quota entry for the "
        "ds service in the region; the default value is not published "
        "elsewhere, so the limit cannot be safely discovered"
    )


def _ds_slow_gate(ctx) -> None:
    # AWS Managed Microsoft AD directory provisioning takes ~20-45 minutes and bills for the
    # full lifetime of the directory, and this check also waits for a new domain controller to
    # become active (up to another 45 minutes per AWS docs). This check deliberately pays that
    # cost to get a real ground-truth answer rather than self-skipping.
    return


def _create_vpc_for_directory(ctx, clock):
    """Adopt the account's default VPC if it already has subnets in >=2 AZs -- the
    account's VPC quota is shared across every concurrently-running check, and a
    directory only needs 2 AZ-diverse subnets, not a dedicated VPC. Only create a
    fresh one if no usable default VPC is available. Returns every AZ-distinct
    subnet the candidate VPC offers (not just 2): Directory Service rejects some
    AZs within a region as "capacity constrained" for AD, so the caller needs
    alternate pairs to retry against rather than a single fixed choice."""
    ec2 = ctx.client("ec2")
    adopted = _default_vpc_subnets_by_az(ec2, ctx=ctx)
    if adopted is not None:
        return adopted

    vpc = ec2.create_vpc(
        CidrBlock="10.190.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", clock, VpcId=vpc_id))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
        if az["State"] == "available"
    ][:4]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not expose 2 available AZs required for a DS directory VPC")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.190.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", clock, SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _default_vpc_subnets_by_az(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        return None
    return vpc_id, list(by_az.values())


def _is_az_capacity_error(e: ClientError) -> bool:
    err = e.response.get("Error", {})
    return err.get("Code") == "ClientException" and "capacity constrained" in err.get("Message", "").lower()


def _create_microsoft_ad(ctx, vpc_id, az_subnet_ids, clock, edition: str = "Standard") -> str:
    if len(az_subnet_ids) < 2:
        raise AssertionError(f"need subnets in >=2 distinct AZs to create a test directory, got {az_subnet_ids}")
    ds = ctx.client("ds")
    # Directory Service can reject an individual AZ as "capacity constrained" for AD even
    # though EC2 lists it as available -- try successive AZ pairs rather than pinning one.
    pairs = [az_subnet_ids[i : i + 2] for i in range(0, len(az_subnet_ids) - 1, 2)]
    last_err: ClientError | None = None
    for pair in pairs:
        name = f"{ctx.unique_name('sim2real-ds-')}.test"
        try:
            resp = ds.create_microsoft_ad(
                Name=name,
                Password=_DS_PASSWORD,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": pair},
                Edition=edition,
            )
        except ClientError as e:
            if _is_az_capacity_error(e) and pair is not pairs[-1]:
                last_err = e
                continue
            raise
        directory_id = resp["DirectoryId"]
        ctx.on_cleanup(lambda: _delete_directory(ctx, directory_id, clock))
        return directory_id
    raise last_err


# One teardown clock per run (a dict run() creates), started by the first teardown that runs: the
# directory delete gets 1440 s of it and the network deletes end by 1740 s, inside the 1800 s budget.
_DIRECTORY_TEARDOWN_S = 1440.0  # a directory with an added controller measured 1146 s from DeleteDirectory to gone
_TEARDOWN_TOTAL_S = 1740.0


def _teardown_start(clock: dict) -> float:
    return clock.setdefault("start", time.monotonic())


def _delete_directory(ctx, directory_id, clock) -> None:
    ds = ctx.client("ds")
    deadline = _teardown_start(clock) + _DIRECTORY_TEARDOWN_S
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            # A directory still being created refuses DeleteDirectory with ClientException.
            if code != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_for_stage(ctx, directory_id, {"Deleted"}, timeout_s=max(deadline - time.monotonic(), 0.0), interval_s=2.0)


def _wait_for_stage(ctx, directory_id, target_stages, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException" and "Deleted" in target_stages:
                return "Deleted"
            raise
        if desc:
            stage = desc[0]["Stage"]
            if stage in target_stages:
                return stage
            if stage == "Failed":
                raise AssertionError(f"directory {directory_id} entered Failed stage while waiting for {target_stages}")
        elif "Deleted" in target_stages:
            return "Deleted"
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s")
        time.sleep(interval_s)


def _wait_for_domain_controller_count(ctx, directory_id, expected_count, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        dcs = ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"]
        live = [d for d in dcs if d["Status"] not in ("Deleting", "Deleted", "Failed")]
        if len(live) >= expected_count:
            return live
        time.sleep(interval_s)
    raise AssertionError(f"domain controller count for {directory_id} never reached {expected_count} within {timeout_s}s")


# A directory in this VPC deletes asynchronously and leaves its ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. Teardown waits (bounded) for the
# ENIs, retries DependencyViolation in one window shared by the check's network deletes, then raises
# naming any ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}


def _delete_net(client, op, clock, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    net_deadline = clock.setdefault("net", _time.monotonic() + _NET_TEARDOWN_S)
    deadline = min(net_deadline, _teardown_start(clock) + _TEARDOWN_TOTAL_S)
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
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
                        f"{op}({ident}): DependencyViolation at the teardown deadline; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


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
