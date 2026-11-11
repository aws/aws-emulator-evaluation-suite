"""update-number-of-domain-controllers-limit-exceeded-blocked."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-number-of-domain-controllers-limit-exceeded-blocked"
GROUP = "overly-permissive"
SERVICES = ["ds"]

_SHARED_AD_NAME = "sim2real-behav-ds-b2-shared-std.example.com"
_SHARED_AD_PASSWORD = "Sim2Real-SharedAD-Pw924!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A domain controller count far above the limit is rejected with
    DomainControllerLimitExceededException and leaves the count unchanged, while a small in-limit
    increase is accepted and the new domain controller appears."""
    directory_id = _get_or_create_shared_directory(ctx, _SHARED_AD_NAME, "Standard")

    ds = ctx.client("ds")
    initial_count = len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"])
    assert initial_count > 0, f"expected the shared directory {directory_id!r} to already have domain controllers, found {initial_count}"
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=initial_count)
        )
    )

    # Negative: a wildly excessive DesiredNumber is rejected rather than silently scaling.
    code = _error_code(
        lambda: ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=999)
    )
    assert code == "DomainControllerLimitExceededException", f"expected DomainControllerLimitExceededException for DesiredNumber=999, got {code!r}"

    # Effect absent: the domain controller count did not change.
    count_after_reject = len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"])
    assert count_after_reject == initial_count, f"expected domain controller count to stay at {initial_count} after the rejected request, found {count_after_reject}"

    # Positive control: a legitimate, small increase is accepted and actually provisions an
    # additional domain controller record (not just a fake 200 OK) -- we only wait for the new
    # domain controller to appear in the list, not for it to finish becoming Active, since
    # that final transition can take much longer than this check's budget.
    _call_with_retry(
        lambda: ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=initial_count + 1)
    )
    _wait_for_domain_controller_count(ctx, directory_id, initial_count + 1, timeout_s=90, interval_s=5)


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


def _error_code(fn, timeout_s=60, interval_s=6):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses is the strongest signal available."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            if _is_transient(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return e.response["Error"]["Code"]
        raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _get_or_create_shared_directory(ctx, name, edition, timeout_s=2200):
    """Idempotently returns the DirectoryId of an Active shared Managed Microsoft AD fixture.
    Provisioning one takes many minutes, so every check that needs *an* Active directory reuses
    the same fixture; 2200s leaves headroom under the suite's 3000s ceiling when this run has to
    create it. The run that creates the directory, VPC and subnets registers their teardown;
    a run that reuses an existing fixture never deletes it."""
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
                ctx.on_cleanup(lambda s=subnet["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=s))
            resp = ds.create_microsoft_ad(
                Name=name,
                Password=_SHARED_AD_PASSWORD,
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
            ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, resp["DirectoryId"]))
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


def _wait_for_domain_controller_count(ctx, directory_id, expected_count, timeout_s=90, interval_s=5):
    """Waits for DescribeDomainControllers to list `expected_count` entries -- i.e. for the new
    domain controller RECORD to appear, not necessarily for it to finish becoming Active."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    count = None
    while time.monotonic() < deadline:
        count = len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"])
        if count >= expected_count:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"domain controller count never reached {expected_count} within {timeout_s}s (last={count})"
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
