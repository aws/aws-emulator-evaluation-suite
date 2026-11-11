"""ca-enrollment-disable-not-enabled-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ca-enrollment-disable-not-enabled-rejected"
GROUP = "server-side"
SERVICES = ["ds"]

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_MSAD_NAME = "sim2real-behav-msad-324808ba.example.com"
_SHARED_PASSWORD = "Sim2Real-Shared-Passw0rd1!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableCAEnrollmentPolicy on a directory that never enabled the policy is rejected
    with EntityDoesNotExistException, DescribeCAEnrollmentPolicy still reports Disabled
    unchanged, and an unrelated directory mutation (tagging) still succeeds (control)."""
    directory_id = _get_shared_active_msad(ctx)
    ds = ctx.client("ds")

    before = _ca_policy_status(ds, directory_id)
    assert before == "Disabled", before

    code, message, request_id = _error(lambda: ds.disable_ca_enrollment_policy(DirectoryId=directory_id))
    assert code == "EntityDoesNotExistException", code
    assert message == (
        f"No CA enrollment info found for directory {directory_id} with Inner Exception: "
        f"NoResultFoundException: No CA enrollment info found for directory {directory_id} "
        f": RequestId: {request_id}"
    ), f"unexpected EntityDoesNotExistException message: {message!r}"

    after = _ca_policy_status(ds, directory_id)
    assert after == "Disabled", after

    # Positive control: the directory is otherwise healthy -- an unrelated mutation succeeds.
    control_key = ctx.unique_name("sim2real-behav-ca-control-")
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": control_key, "Value": "ok"}])
    ctx.on_cleanup(
        lambda: ds.remove_tags_from_resource(ResourceId=directory_id, TagKeys=[control_key])
    )
    tags_after = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    assert any(t["Key"] == control_key and t["Value"] == "ok" for t in tags_after)


# ===== helpers =====

def _ca_policy_status(ds, directory_id):
    try:
        resp = ds.describe_ca_enrollment_policy(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityDoesNotExistException":
            return "Disabled"
        raise
    return resp.get("CaEnrollmentPolicyStatus", "Disabled")


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


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId). Raises if the call succeeded."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message"), request_id
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


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
