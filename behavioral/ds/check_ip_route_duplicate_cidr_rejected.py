"""ip-route-duplicate-cidr-rejected."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ip-route-duplicate-cidr-rejected"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-adding an existing CIDR via AddIpRoutes fails with ClientException (not
    EntityAlreadyExistsException) and the exact "already exist" message, the CIDR keeps one
    route, and a distinct CIDR on the same directory is still added."""
    ds = ctx.client("ds")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    # RFC1918 CIDRs can be rejected as overlapping ranges already used by other VPCs in the
    # account; TEST-NET-2 (RFC 5737) is never used by a real VPC. Randomized because the
    # shared directory persists between runs.
    octet = random.randint(1, 250)
    cidr = f"198.51.{octet}.0/24"
    other_cidr = f"198.51.{(octet % 250) + 1}.0/24"
    _ensure_route_absent(ctx, directory_id, cidr)
    _ensure_route_absent(ctx, directory_id, other_cidr)
    _retry_directory_busy(lambda: ds.add_ip_routes(
        DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr, "Description": "sim2real-behav"}]
    ))
    ctx.on_cleanup(lambda: _best_effort(lambda: ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr])))
    _wait_route_status(ctx, directory_id, cidr, {"Added"}, {"AddFailed"})

    code, message, request_id = _error_detail_retry_busy(
        lambda: ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr, "Description": "dup"}])
    )
    assert code == "ClientException", (
        f"expected AddIpRoutes to reject re-adding an already-added CIDR with a ClientException, "
        f"got code={code!r} message={message!r}"
    )
    expected = (
        f"The IP route(s) [{cidr}] already exist. If you want to recreate them, please delete "
        f"the existing routes first. : RequestId: {request_id}"
    )
    assert message == expected, (
        f"expected AddIpRoutes to refuse the duplicate CIDR with {expected!r}, got {message!r}"
    )

    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    dup_count = sum(1 for r in routes if r["CidrIp"] == cidr)
    assert dup_count == 1, f"expected exactly one route for {cidr} after the rejected duplicate, got {dup_count}"

    _retry_directory_busy(lambda: ds.add_ip_routes(
        DirectoryId=directory_id, IpRoutes=[{"CidrIp": other_cidr, "Description": "sim2real-behav-2"}]
    ))
    ctx.on_cleanup(lambda: _best_effort(lambda: ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[other_cidr])))
    other = _wait_route_status(ctx, directory_id, other_cidr, {"Added"}, {"AddFailed"})
    assert other["IpRouteStatusMsg"] == "Added", (
        f"positive control: distinct CIDR {other_cidr} on the same directory ended in "
        f"status {other['IpRouteStatusMsg']!r}, not Added"
    )


def _ds_password() -> str:
    return "Sim2Real-Behav!9Qx"


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _best_effort(fn) -> None:
    """Teardown only: run fn() and tolerate any ClientError (the resource may already be gone)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _retry_directory_busy(fn, timeout_s: float = 300.0, delay_s: float = 10.0):
    """Retry fn() while AWS rejects it with DirectoryUnavailableException (another mutating
    call on the shared directory is in flight); deadline-bounded, as busy can last minutes."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DirectoryUnavailableException":
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _error_detail_retry_busy(fn, timeout_s: float = 300.0, delay_s: float = 10.0):
    """Like _client_error, but retries a transient DirectoryUnavailableException instead of
    mistaking directory-busy for the expected rejection. Returns (code, message, request_id)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code == "DirectoryUnavailableException" and time.monotonic() < deadline:
                time.sleep(delay_s)
                continue
            request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
            return code, err.get("Message") or "", request_id
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _tag_spec(rtype: str, name: str) -> list:
    return [{
        "ResourceType": rtype,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    }]


def _create_vpc_with_subnets(ctx, cidr: str = "10.87.0.0/16"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-ds-vpc-"))
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_ec2_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.87.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", ctx.unique_name(f"sim2real-ds-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        ctx.on_cleanup(lambda sid=subnet_id: _delete_ec2_retrying(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _delete_ec2_retrying(fn, attempts: int = 12, delay_s: float = 15.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("DependencyViolation", "InvalidParameterValue"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    if last_exc:
        raise last_exc


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            raise AssertionError(f"directory {directory_id} vanished from DescribeDirectories while waiting")
        desc = descs[0]
        last_stage = desc["Stage"]
        if last_stage in terminal_ok:
            return desc
        if last_stage in terminal_bad:
            raise AssertionError(f"directory {directory_id} reached {last_stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage={last_stage} after {timeout_s}s")


def _delete_directory_and_wait(ctx, directory_id, timeout_s=1800.0, interval_s=20.0) -> None:
    ds = ctx.client("ds")
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "EntityDoesNotExistException":
            raise AssertionError(f"unexpected error deleting directory: {code}") from exc
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ds.describe_directories(DirectoryIds=[directory_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
                return
            raise
        descs = resp.get("DirectoryDescriptions", [])
        if not descs or descs[0]["Stage"] == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} was not removed/Deleted within {timeout_s}s")


_SHARED_MAD_NAME = "sim2dssharedmad.sim2real.test"
_SHARED_VPC_TAG_NAME = "sim2real-ds-shared-vpc"


def _find_directory_id_by_name(ctx, name):
    ds = ctx.client("ds")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = ds.describe_directories(**kwargs)
        for desc in resp.get("DirectoryDescriptions", []):
            if desc.get("Name") == name and desc.get("Stage") not in ("Deleting", "Deleted"):
                return desc["DirectoryId"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


def _get_or_create_shared_vpc(ctx):
    """Find the shared VPC by tag before creating one, so concurrent checks share a single
    VPC instead of exhausting the per-region VPC quota. Registers cleanup only for the VPC and
    subnets this run creates."""
    ec2 = ctx.client("ec2")

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [_SHARED_VPC_TAG_NAME]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    if not vpcs:
        try:
            created_vpc_id = ec2.create_vpc(
                CidrBlock="10.90.0.0/16",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": _SHARED_VPC_TAG_NAME},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Vpc"]["VpcId"]
            ctx.on_cleanup(lambda: _delete_ec2_retrying(lambda: ec2.delete_vpc(VpcId=created_vpc_id)))
        except ClientError:
            pass
        for _ in range(15):
            vpcs = _existing()
            if vpcs:
                break
            time.sleep(2)
    if not vpcs:
        raise AssertionError("failed to create or find the shared sim2real-ds VPC")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids[:2]

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    for i, az in enumerate(azs):
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.90.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": f"{_SHARED_VPC_TAG_NAME}-subnet{i}"},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                continue
            raise
        ctx.on_cleanup(lambda sid=subnet_id: _delete_ec2_retrying(lambda: ec2.delete_subnet(SubnetId=sid)))
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    return vpc_id, subnet_ids[:2]


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    """Reuse a shared Managed Microsoft AD directory instead of a ~20-45 min create per check.
    Waits up to 2700 s for Active; only the run that created the directory deletes it."""
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx)
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_ds_password(),
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
            ctx.on_cleanup(lambda: _delete_directory_and_wait(ctx, resp["DirectoryId"]))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is None:
                    raise
            else:
                raise
    return _wait_directory_stage(
        ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=2700.0, interval_s=10.0
    )["DirectoryId"]


def _route_entry(ctx, directory_id, cidr):
    ds = ctx.client("ds")
    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matches = [r for r in routes if r["CidrIp"] == cidr]
    return matches[0] if matches else None


def _ensure_route_absent(ctx, directory_id, cidr, timeout_s=300.0, interval_s=10.0):
    """Remove the CIDR if a prior run left it on the shared directory (its non-retrying
    teardown can fail with DirectoryUnavailableException)."""
    ds = ctx.client("ds")
    if _route_entry(ctx, directory_id, cidr) is None:
        return
    _retry_directory_busy(lambda: ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr]))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _route_entry(ctx, directory_id, cidr) is None:
            return
        time.sleep(interval_s)
    raise AssertionError(f"stale route {cidr} from a prior run was not removed within {timeout_s}s")


def _wait_route_status(ctx, directory_id, cidr, terminal_ok, terminal_bad, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        entry = _route_entry(ctx, directory_id, cidr)
        if entry is None:
            raise AssertionError(f"route {cidr} not present in ListIpRoutes while waiting")
        last = entry["IpRouteStatusMsg"]
        if last in terminal_ok:
            return entry
        if last in terminal_bad:
            raise AssertionError(f"route {cidr} reached unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"route {cidr} stuck at status={last} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
