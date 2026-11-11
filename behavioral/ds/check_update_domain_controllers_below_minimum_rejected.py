"""update-domain-controllers-below-minimum-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "update-domain-controllers-below-minimum-rejected"
GROUP = "overly-permissive"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateNumberOfDomainControllers with DesiredNumber=1 (minimum 2) is refused, not clamped:
    ValidationException with the exact message, the controller count stays 2, and
    DesiredNumber=2 still succeeds."""
    ds = ctx.client("ds")
    directory_id = _create_active_microsoft_ad(ctx)

    before_count = len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"])
    assert before_count == 2, f"expected the default 2 domain controllers, found {before_count}"

    # botocore would refuse DesiredNumber=1 client-side, so bypass its validation to test the
    # service's own rejection: a ValidationException, which is not in the modeled error list.
    code, message = _error_no_validation(
        ds, "update_number_of_domain_controllers", DirectoryId=directory_id, DesiredNumber=1
    )
    assert code == "ValidationException", f"unexpected error code: {code}"
    expected_message = (
        "1 validation error detected: Value '1' at 'desiredNumber' failed to satisfy "
        "constraint: Member must have value greater than or equal to 2"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_count = len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"])
    assert after_count == 2, (
        f"the rejected DesiredNumber=1 call must not remove a domain controller, found {after_count}"
    )

    # Positive control: a valid (unchanged) DesiredNumber is accepted.
    ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=2)


# ===== helpers =====


def _vpc_az_subnets(ec2, vpc_id: str, *, ctx) -> dict[str, str]:
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    return by_az


def _default_vpc_az_subnets(ec2, *, ctx) -> dict[str, Any] | None:
    """The run's shared network with its supported-AZ subnets, or None if under two AZs.
    Preferred over a dedicated VPC, which would spend the small per-region VPC quota."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    by_az = _vpc_az_subnets(ec2, vpc_id, ctx=ctx)
    if len(by_az) < 2:
        return None
    return {"vpc_id": vpc_id, "az_subnets": by_az}


def _create_vpc_with_subnets(ctx) -> dict[str, Any]:
    ec2 = ctx.client("ec2")

    adopted = _default_vpc_az_subnets(ec2, ctx=ctx)
    if adopted is not None:
        return adopted

    tag = ctx.unique_name("sim2real-ds-")
    vpc = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # Create subnets in every available AZ (not just 2): Managed Microsoft AD refuses a
    # capacity-constrained AZ with a ClientException naming the offending subnet, and
    # _create_active_microsoft_ad needs a spare AZ pair to retry into when that happens.
    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ]
    az_subnets: dict[str, str] = {}
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.0.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{tag}{i}"}]}
            ],
        )
        az_subnets[az] = subnet["Subnet"]["SubnetId"]

    def _cleanup() -> None:
        """Teardown: delete every subnet, then the VPC, tolerating only their not-found; raise any
        other failure once every delete has been attempted."""
        failures: list[ClientError] = []
        for sid in az_subnets.values():
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidSubnetID.NotFound":
                    failures.append(exc)
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidVpcID.NotFound":
                raise
        if failures:
            raise failures[0]

    ctx.on_cleanup(_cleanup)
    return {"vpc_id": vpc_id, "az_subnets": az_subnets}


def _create_active_microsoft_ad(ctx) -> str:
    from botocore.exceptions import ClientError

    ds = ctx.client("ds")
    net = _create_vpc_with_subnets(ctx)
    vpc_id = net["vpc_id"]
    az_subnets = dict(net["az_subnets"])
    name = f"{ctx.unique_name('sim2real-ds-')}.test"

    directory_id = None
    last_exc: ClientError | None = None
    while len(az_subnets) >= 2:
        pair_azs = list(az_subnets)[:2]
        subnet_ids = [az_subnets[az] for az in pair_azs]
        try:
            resp = ds.create_microsoft_ad(
                Name=name,
                Password="TestPassw0rd!2345",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
            break
        except ClientError as exc:
            error = exc.response.get("Error", {})
            message = error.get("Message", "")
            # Managed Microsoft AD does not support every AZ (a capacity constraint, not a request
            # defect) and names the offending subnet; drop that AZ and retry with the next pair.
            offending_az = next(
                (az for az, sid in az_subnets.items() if sid in message), None
            )
            if error.get("Code") == "ClientException" and offending_az is not None:
                last_exc = exc
                del az_subnets[offending_az]
                continue
            raise
    if directory_id is None:
        raise last_exc or AssertionError(
            "no AZ pair in the VPC was accepted for a Microsoft AD directory"
        )

    ctx.on_cleanup(lambda: _safe_delete_directory(ds, directory_id))
    stage = _wait_for_directory_stage(
        ds, directory_id, {"Active", "Failed", "Impaired"}, timeout_s=3600.0, interval_s=30.0
    )
    if stage != "Active":
        raise AssertionError(f"prerequisite Microsoft AD directory did not reach Active (got {stage!r})")
    return directory_id


def _wait_for_directory_stage(
    ds, directory_id: str, target_stages: set[str], timeout_s: float = 3600.0, interval_s: float = 30.0
) -> str | None:
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
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach {target_stages}, last stage={last_stage}")


def _error_no_validation(client, method_name: str, **kwargs):
    """Call client.method_name(**kwargs) bypassing client-side validation; return (code, message).
    botocore bakes validation into the serializer at construction, so the decorator's inner
    serializer is swapped in for the call. An unexpected success raises."""
    from botocore.exceptions import ClientError

    decorator = client._serializer
    inner = getattr(decorator, "_serializer", decorator)
    client._serializer = inner
    try:
        result = getattr(client, method_name)(**kwargs)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    finally:
        client._serializer = decorator
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
    deadline = time.monotonic() + 1800.0
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


# A deleted directory releases its ENIs asynchronously, so an immediate DeleteSubnet / DeleteVpc
# fails DependencyViolation. Teardown waits (bounded) for the ENIs to go, retries inside one window
# shared by all of a check's network deletes, and raises naming the ENIs still attached.
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
