"""reset-user-password-nonexistent-user-rejected."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reset-user-password-nonexistent-user-rejected"
GROUP = "overly-permissive"
SERVICES = ["ds"]

_SHARED_AD_NAME = "sim2real-behav-ds-b2-shared-std.example.com"
_SHARED_AD_PASSWORD = "Sim2Real-SharedAD-Pw924!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResetUserPassword for a user the directory does not have fails with UserDoesNotExistException and
    "User: <name> does not exist.", while resetting the built-in Admin's password on the same directory
    succeeds."""
    directory_id = _get_or_create_shared_directory(ctx, _SHARED_AD_NAME, "Standard")

    ds = ctx.client("ds")
    bogus_user = ctx.unique_name("no-such-user-")

    # Negative: resetting the password of a user that does not exist is rejected.
    code, message, request_id = _error(
        lambda: ds.reset_user_password(
            DirectoryId=directory_id, UserName=bogus_user, NewPassword="Sim2Real-Bogus-Pw924!"
        ),
        timeout_s=150,
    )
    assert code == "UserDoesNotExistException", f"expected UserDoesNotExistException, got {code}"
    expected = _USER_MISSING.format(user=bogus_user, request_id=request_id)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Positive control: the directory's real built-in Admin account exists and its password
    # can genuinely be reset, proving the earlier rejection was specific to the nonexistent
    # user rather than the operation being universally blocked on this directory.
    _call_with_retry(
        lambda: ds.reset_user_password(DirectoryId=directory_id, UserName="Admin", NewPassword="Sim2Real-Ctrl-Pw924!")
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


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


_USER_MISSING = "User: {user} does not exist. : RequestId: {request_id}"


def _error(fn, timeout_s=60, interval_s=6):
    """Returns the rejected call's (error code, message, request id). An unexpected SUCCESS raises, because
    an over-permissive target accepting input real AWS refuses is the strongest signal available."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            if _is_transient(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return (
                e.response["Error"]["Code"],
                e.response["Error"].get("Message"),
                e.response.get("ResponseMetadata", {}).get("RequestId", ""),
            )
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


def _get_or_create_shared_directory(ctx, name, edition, timeout_s=200):
    """The DirectoryId of the Active shared Managed Microsoft AD, created on first use and found by
    name afterwards: provisioning takes 20-45 minutes, so checks that only need an Active directory
    share one. No single check deletes it."""
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
            resp = ds.create_microsoft_ad(
                Name=name,
                Password=_SHARED_AD_PASSWORD,
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
        except ClientError:
            # Lost the create race with a concurrently running check (duplicate
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
