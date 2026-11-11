"""ca-enrollment-policy-toggle-server-managed."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ca-enrollment-policy-toggle-server-managed"
GROUP = "server-side"
SERVICES = ["ds"]

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_MSAD_NAME = "sim2real-behav-msad-d24ce4fe.example.com"
_SHARED_PASSWORD = "Sim2Real-Shared-Passw0rd1!"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableCAEnrollmentPolicy with a nonexistent PcaConnectorArn and DisableCAEnrollmentPolicy on a
    never-enabled policy are both rejected server-side, and DescribeCAEnrollmentPolicy keeps
    reporting Disabled throughout."""
    directory_id = _get_shared_active_msad(ctx)
    ds = ctx.client("ds")

    baseline = _ca_policy_status(ds, directory_id)
    assert baseline == "Disabled", baseline

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:pca-connector-ad:{ctx.region}:{account_id}:connector/{uuid.uuid4()}"
    code, _message, _ = _error(
        lambda: ds.enable_ca_enrollment_policy(DirectoryId=directory_id, PcaConnectorArn=bogus_arn)
    )
    # message varies: it embeds the request id of DS's own downstream pca-connector-ad call,
    # which no response field exposes.
    assert code == "EntityDoesNotExistException", code

    after_enable = _ca_policy_status(ds, directory_id)
    assert after_enable == "Disabled", after_enable

    code2, message2, request_id2 = _error(lambda: ds.disable_ca_enrollment_policy(DirectoryId=directory_id))
    assert code2 == "EntityDoesNotExistException", code2
    assert message2 == (
        f"No CA enrollment info found for directory {directory_id} with Inner Exception: "
        f"NoResultFoundException: No CA enrollment info found for directory {directory_id} "
        f": RequestId: {request_id2}"
    ), f"unexpected EntityDoesNotExistException message: {message2!r}"

    after_disable = _ca_policy_status(ds, directory_id)
    assert after_disable == "Disabled", after_disable


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
