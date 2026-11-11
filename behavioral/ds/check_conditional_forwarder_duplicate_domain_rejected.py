"""conditional-forwarder-duplicate-domain-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conditional-forwarder-duplicate-domain-rejected"
GROUP = "state-machine"
SERVICES = ["ds"]

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_MSAD_NAME = "sim2real-behav-msad-8e438cd4.example.com"
_MSAD_PASSWORD = "Sim2Real-Check-Passw0rd1!"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second conditional forwarder for a RemoteDomainName that already has one is refused with
    EntityAlreadyExistsException and AWS's zone-exists message, the original's DNS IPs stay unchanged,
    and a forwarder for a different domain on the same directory still succeeds."""
    ds = ctx.client("ds")
    directory_id = _get_active_msad(ctx)

    remote_domain = f"{ctx.unique_name('dup-forwarder-')}.test"
    _retry_directory_busy(lambda: ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=["203.0.113.5"]
    ))
    ctx.on_cleanup(lambda: _delete_forwarder(ds, directory_id, remote_domain))

    code, message, request_id = _error_retry_busy(
        lambda: ds.create_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=remote_domain, DnsIpAddrs=["203.0.113.9"]
        )
    )
    assert code == "EntityAlreadyExistsException", code
    # The message names the directory's DNS server, which the check cannot know, so the parts
    # around it are exact.
    assert message.startswith(f"Failed to create zone {remote_domain} on server ") and message.endswith(
        f". A conditional forwarding zone already exists for that name.  : RequestId: {request_id}"
    ), f"unexpected EntityAlreadyExistsException message: {message!r}"

    # effect absent: the original DNS IPs were not overwritten by the rejected duplicate.
    listed = ds.describe_conditional_forwarders(DirectoryId=directory_id)["ConditionalForwarders"]
    matches = [cf for cf in listed if cf["RemoteDomainName"] == remote_domain]
    assert len(matches) == 1
    assert matches[0]["DnsIpAddrs"] == ["203.0.113.5"]

    # positive control: a forwarder for a different domain on the same directory succeeds.
    other_domain = f"{ctx.unique_name('other-forwarder-')}.test"
    _retry_directory_busy(lambda: ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=other_domain, DnsIpAddrs=["203.0.113.7"]
    ))
    ctx.on_cleanup(lambda: _delete_forwarder(ds, directory_id, other_domain))
    listed2 = ds.describe_conditional_forwarders(DirectoryId=directory_id)["ConditionalForwarders"]
    assert any(cf["RemoteDomainName"] == other_domain for cf in listed2)


def _retry_directory_busy(fn, attempts: int = 6, delay_s: float = 15.0):
    """Run fn(), retrying while the directory answers busy: DirectoryUnavailableException
    (another mutation in flight) or ServiceException (an internal error while it is busy)."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "DirectoryUnavailableException", "ServiceException"
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _error_retry_busy(fn, attempts: int = 6, delay_s: float = 15.0):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise, retrying while the
    directory answers busy (DirectoryUnavailableException / ServiceException). A success raises."""
    for _ in range(attempts):
        try:
            resp = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") in ("DirectoryUnavailableException", "ServiceException"):
                time.sleep(delay_s)
                continue
            return err.get("Code"), err.get("Message", ""), exc.response["ResponseMetadata"]["RequestId"]
        raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")
    raise AssertionError(f"the directory still answered busy after {attempts} attempts")


def _delete_forwarder(ds, directory_id, remote_domain):
    """Teardown: delete the forwarder; already gone (EntityDoesNotExistException) is fine."""
    try:
        ds.delete_conditional_forwarder(DirectoryId=directory_id, RemoteDomainName=remote_domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


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


def _get_active_msad(ctx, budget_s=2700.0, interval_s=2.0):
    """Look up (or create) this check's Managed Microsoft AD directory and wait until it is Active.
    Real creation takes 20-45 minutes. The name is unique to this check, so the directory is deleted
    at cleanup whether this call created it or found it."""
    ds = ctx.client("ds")
    found = _find_directory_by_name(ctx, _MSAD_NAME)
    if found is None:
        vpc_id, subnet_ids = _default_vpc_two_azs(ctx)
        try:
            directory_id = ds.create_microsoft_ad(
                Name=_MSAD_NAME,
                Password=_MSAD_PASSWORD,
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )["DirectoryId"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExistsException":
                raise
            found = _find_directory_by_name(ctx, _MSAD_NAME)
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
                f"directory {directory_id} is in terminal stage "
                f"{found['Stage']!r}; it needs manual cleanup before this check can run"
            )
        if found["Stage"] == "Active":
            return directory_id

    deadline = time.monotonic() + min(budget_s, ctx.time_left())
    stage = None
    while time.monotonic() < deadline:
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        stage = descs[0]["Stage"] if descs else None
        if stage == "Active":
            return directory_id
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} reached {stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} still {stage!r} after {budget_s}s"
    )


def _delete_directory_and_wait(ds, directory_id, timeout_s=1800.0, interval_s=2.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""

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
