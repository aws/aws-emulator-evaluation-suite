"""add-ip-routes-duplicate-rejected."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-ip-routes-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]

_SHARED_AD_NAME = "sim2real-behav-ds-b2-shared-std.example.com"
_SHARED_AD_PASSWORD = "Sim2Real-SharedAD-Pw924!"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddIpRoutes with an existing CIDR fails with ClientException naming that CIDR (not the modeled
    EntityAlreadyExistsException) and keeps one route; after RemoveIpRoutes the same CIDR adds once, and
    a distinct CIDR adds throughout."""
    directory_id = _get_or_create_shared_directory(ctx, _SHARED_AD_NAME, "Standard")

    ds = ctx.client("ds")
    octet = random.randint(1, 250)
    cidr_a = f"198.51.{octet}.0/24"
    cidr_b = f"203.0.{octet}.0/24"
    ctx.on_cleanup(lambda: _safe(lambda: ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr_a])))
    ctx.on_cleanup(lambda: _safe(lambda: ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr_b])))

    # Positive control: adding the first route succeeds, and settles at Added (not merely
    # accepted) before we rely on its presence to test rejection.
    _call_with_retry(
        lambda: ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr_a, "Description": "route-a"}]),
        timeout_s=300,
    )
    _wait_route_status(ds, directory_id, cidr_a, "Added", timeout_s=180)

    # Negative: re-adding the same CIDR while it is still routed is rejected. AWS answers this with
    # ClientException (not the modeled EntityAlreadyExistsException), naming the duplicate CIDR and
    # telling the caller to delete it first; the exact message keeps this specific to "already
    # routed", not any other ClientException cause (a still-transient one is retried away).
    code, message, request_id = _error_code_and_message(
        lambda: ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr_a, "Description": "dup"}]),
        timeout_s=300,
    )
    assert code == "ClientException", (
        f"expected ClientException re-adding already-routed {cidr_a}, got {code!r} message={message!r}"
    )
    assert message == (
        f"The IP route(s) [{cidr_a}] already exist. If you want to recreate them, please delete "
        f"the existing routes first. : RequestId: {request_id}"
    ), f"unexpected duplicate-route message: {message!r}"

    # Effect absent: still exactly one route for that CIDR.
    routes_after = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matching_after = [r for r in routes_after if r["CidrIp"] == cidr_a]
    assert len(matching_after) == 1, f"expected exactly one route entry for {cidr_a}, found {matching_after}"

    # Restore: the rejection is specific to the existing route, not a wholesale block on the
    # CIDR — removing it and re-adding the identical CidrIp must now succeed.
    _call_with_retry(lambda: ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr_a]), timeout_s=300)
    _wait_route_absent(ds, directory_id, cidr_a, timeout_s=180)
    _call_with_retry(
        lambda: ds.add_ip_routes(
            DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr_a, "Description": "route-a-restored"}]
        ),
        timeout_s=300,
    )
    _wait_route_status(ds, directory_id, cidr_a, "Added", timeout_s=180)
    routes_restored = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    live_restored = [r for r in routes_restored if r["CidrIp"] == cidr_a and r["IpRouteStatusMsg"] != "Removed"]
    assert len(live_restored) == 1, f"expected {cidr_a} to be re-added exactly once, found {live_restored}"

    # Positive control 2: a distinct CIDR can still be added, proving the directory is not
    # wholesale blocking route additions.
    _call_with_retry(
        lambda: ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr_b, "Description": "route-b"}]),
        timeout_s=300,
    )
    routes_final = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matching_final = [r for r in routes_final if r["CidrIp"] == cidr_b]
    assert len(matching_final) == 1, f"expected exactly one route entry for {cidr_b}, found {matching_final}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _is_transient(exc: ClientError) -> bool:
    err = exc.response.get("Error", {})
    code = err.get("Code", "")
    msg = err.get("Message", "").lower()
    if code in ("DirectoryUnavailableException", "VpcLimitExceeded"):
        return True
    if code == "ClientException" and any(
        m in msg for m in ("maintenance", "already in progress", "please wait", "try again")
    ):
        return True
    return False


def _call_with_retry(fn, timeout_s=60, interval_s=6):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if _is_transient(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _error_code_and_message(fn, timeout_s=60, interval_s=6):
    """Call fn() past transient errors; return (Error.Code, Error.Message, RequestId). Raises if
    the call succeeded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = fn()
        except ClientError as e:
            if _is_transient(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            err = e.response.get("Error", {})
            request_id = (e.response.get("ResponseMetadata") or {}).get("RequestId")
            return err.get("Code"), err.get("Message"), request_id
        raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


def _wait_route_status(ds, directory_id, cidr, ok_status, timeout_s=180, interval_s=6):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        matches = [r for r in routes if r["CidrIp"] == cidr]
        last = matches[0]["IpRouteStatusMsg"] if matches else None
        if last == ok_status:
            return matches[0]
        if last in ("AddFailed", "RemoveFailed"):
            raise AssertionError(f"route {cidr} on {directory_id} entered {last}, expected {ok_status}")
        time.sleep(interval_s)
    raise AssertionError(f"route {cidr} on {directory_id} did not reach {ok_status} within {timeout_s}s (last={last!r})")


def _wait_route_absent(ds, directory_id, cidr, timeout_s=180, interval_s=6):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        matches = [r for r in routes if r["CidrIp"] == cidr]
        if not matches:
            return
        last = matches[0]["IpRouteStatusMsg"]
        if last == "Removed":
            return
        if last == "RemoveFailed":
            raise AssertionError(f"route {cidr} on {directory_id} entered RemoveFailed while waiting for removal")
        time.sleep(interval_s)
    raise AssertionError(f"route {cidr} on {directory_id} still present ({last!r}) after {timeout_s}s")


def _find_directory_by_name(ds, name):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = ds.describe_directories(**kwargs)
        for d in resp.get("DirectoryDescriptions", []):
            if d.get("Name") == name and d.get("Stage") != "Deleted":
                return d
        token = resp.get("NextToken")
        if not token:
            return None


def _get_or_create_shared_directory(ctx, name, edition, timeout_s=2700):
    """Idempotently returns the DirectoryId of an Active shared Managed Microsoft AD fixture.
    Real provisioning takes real minutes on AWS, so a check that just needs *an* Active
    directory reuses an existing fixture instead of paying that cost once per check.
    The call that creates the fixture registers its teardown (directory, then subnets and VPC).
    The default budget must cover a cold creation (observed ~1600s for MicrosoftAD Standard to
    reach Active), not just the wait for a sibling check's already-in-flight create."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    existing = _find_directory_by_name(ds, name)
    if existing is not None and existing.get("Stage") == "Failed":
        raise AssertionError(
            f"shared fixture directory {existing['DirectoryId']!r} ({name}) is in Failed "
            "stage; delete it manually before re-running this batch"
        )
    directory_id = existing["DirectoryId"] if existing is not None else None
    if directory_id is None:
        try:
            ec2 = ctx.client("ec2")
            octet = random.randint(0, 200)
            vpc = ec2.create_vpc(
                CidrBlock=f"10.{octet}.0.0/23",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ds-shared-vpc-")}],
                }],
            )["Vpc"]
            vpc_id = vpc["VpcId"]
            ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
            azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
            subnet_ids = []
            for i, az in enumerate(azs):
                subnet = ec2.create_subnet(
                    VpcId=vpc_id,
                    CidrBlock=f"10.{octet}.{i}.0/24",
                    AvailabilityZone=az,
                    TagSpecifications=[{
                        "ResourceType": "subnet",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ds-shared-subnet-")}],
                    }],
                )["Subnet"]
                subnet_ids.append(subnet["SubnetId"])
                ctx.on_cleanup(lambda sid=subnet["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid))
            resp = ds.create_microsoft_ad(
                Name=name,
                Password=_SHARED_AD_PASSWORD,
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
                Tags=[{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
            )
            directory_id = resp["DirectoryId"]
            ctx.on_cleanup(lambda d=directory_id: _delete_directory_and_wait(ds, d))
        except ClientError:
            # Lost the create race with a concurrently-running check in this batch (duplicate
            # name, VPC/directory quota momentarily exhausted by a sibling attempt, etc.) --
            # fall back to waiting for whichever check wins the race to finish creating it.
            directory_id = None
            while directory_id is None and time.monotonic() < deadline:
                time.sleep(2)
                found = _find_directory_by_name(ds, name)
                if found is not None:
                    directory_id = found["DirectoryId"]
            if directory_id is None:
                raise

    remaining = max(30.0, deadline - time.monotonic())
    return _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=remaining)["DirectoryId"]


def _wait_directory_stage(ctx, directory_id, target_stages, failure_stages, timeout_s=260, interval_s=10):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in failure_stages:
            raise AssertionError(f"directory {directory_id} entered {stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={desc})"
    )


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


def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=2.0):
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
