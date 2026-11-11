"""directory-data-access-toggle-server-managed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "directory-data-access-toggle-server-managed"
GROUP = "server-side"
SERVICES = ["ds"]

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_MSAD_NAME = "sim2real-behav-msad-ef17e48a.example.com"
_SHARED_PASSWORD = "Sim2Real-Shared-Passw0rd1!"


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DataAccessStatus moves Disabled -> Enabling -> Enabled -> Disabling -> Disabled as
    DescribeDirectoryDataAccess reports, and a repeated EnableDirectoryDataAccess is rejected
    server-side without changing the status."""
    directory_id = _get_shared_active_msad(ctx)
    ds = ctx.client("ds")

    initial = ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"]
    if initial == "Enabled":
        _retry_directory_busy(lambda: ds.disable_directory_data_access(DirectoryId=directory_id))
        _poll_until(
            lambda: ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"],
            lambda status: status == "Disabled",
            timeout_s=180.0,
            interval_s=10.0,
        )
        initial = "Disabled"
    assert initial == "Disabled", f"expected initial DataAccessStatus Disabled, got {initial!r}"

    _retry_directory_busy(lambda: ds.enable_directory_data_access(DirectoryId=directory_id))
    enabled = _poll_until(
        lambda: ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"],
        lambda status: status in ("Enabled", "Failed"),
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert enabled == "Enabled", f"expected DataAccessStatus Enabled after enable, got {enabled!r}"

    code, message, request_id = _error(lambda: ds.enable_directory_data_access(DirectoryId=directory_id))
    assert code == "DirectoryInDesiredStateException", (
        "expected DirectoryInDesiredStateException re-enabling an already-enabled directory, "
        f"got {code!r}"
    )
    expected_message = f"Directory {directory_id} is already in the desired state. : RequestId: {request_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    unchanged = ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"]
    assert unchanged == "Enabled", (
        f"a rejected repeat EnableDirectoryDataAccess must leave DataAccessStatus Enabled, got {unchanged!r}"
    )

    _retry_directory_busy(lambda: ds.disable_directory_data_access(DirectoryId=directory_id))
    disabled = _poll_until(
        lambda: ds.describe_directory_data_access(DirectoryId=directory_id)["DataAccessStatus"],
        lambda status: status == "Disabled",
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert disabled == "Disabled", f"expected DataAccessStatus Disabled after disable, got {disabled!r}"


# ===== helpers =====

def _error(fn):
    """Call fn(); return the (Code, Message, RequestId) of the ClientError it raises. A
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_directory_busy(fn, attempts: int = 10, delay_s: float = 12.0):
    """The shared directory fixture may be mutated by several checks in this run in
    sequence; a mutating call can transiently fail with DirectoryUnavailableException
    (another mutation still settling) or ServiceException. Retry with backoff rather
    than treat a transient collision as a real fidelity finding."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("DirectoryUnavailableException", "ServiceException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _default_vpc_two_azs(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("need subnets in at least 2 distinct AZs to create a test directory")
    azs = sorted(by_az)
    return vpc_id, [by_az[azs[0]], by_az[azs[1]]]


def _find_directory_by_name(ctx, name):
    ds = ctx.client("ds")
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = ds.describe_directories(**kwargs)
        for d in resp.get("DirectoryDescriptions", []):
            if d["Name"] == name:
                return d
        token = resp.get("NextToken")
        if not token:
            return None


def _get_shared_active_msad(ctx, budget_s=2700.0, interval_s=20.0):
    """Look up (or create) the shared Managed Microsoft AD fixture and wait until it is Active.
    Real creation takes 20-45 minutes. The name is unique to this check, so the directory is deleted
    at cleanup whether this call created it or found it."""
    ds = ctx.client("ds")
    found = _find_directory_by_name(ctx, _SHARED_MSAD_NAME)
    if found is None:
        vpc_id, subnet_ids = _default_vpc_two_azs(ctx)
        try:
            directory_id = ds.create_microsoft_ad(
                Name=_SHARED_MSAD_NAME,
                Password=_SHARED_PASSWORD,
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )["DirectoryId"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExistsException":
                raise
            found = _find_directory_by_name(ctx, _SHARED_MSAD_NAME)
            if found is None:
                raise
            directory_id = found["DirectoryId"]
        ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    else:
        directory_id = found["DirectoryId"]
        # The name is unique to this check, so a directory found here is a leftover of an
        # earlier run of it, and this run removes it.
        ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
        if found["Stage"] in ("Failed", "Inoperable"):
            raise AssertionError(
                f"shared fixture directory {directory_id} is in terminal stage "
                f"{found['Stage']!r}; needs manual cleanup before this fixture can be reused"
            )
        if found["Stage"] == "Active":
            return directory_id

    deadline = time.monotonic() + budget_s
    stage = None
    while time.monotonic() < deadline:
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        stage = descs[0]["Stage"] if descs else None
        if stage == "Active":
            return directory_id
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"shared fixture directory {directory_id} reached {stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"shared fixture directory {directory_id} still {stage!r} after {budget_s}s"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_directory_and_wait(ds, directory_id, timeout_s=1800.0, interval_s=30.0):
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
                except ClientError as share_err:
                    if share_err.response["Error"]["Code"] != "EntityDoesNotExistException":
                        raise
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as unshare_err:
                        if unshare_err.response["Error"]["Code"] not in (
                            "EntityDoesNotExistException", "DirectoryNotSharedException",
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
