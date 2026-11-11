"""share-directory-already-shared-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Directory Service cannot place domain controllers in these zones (CreateMicrosoftAD: "Failed to
# locate Availability Zone: us-west-2d"); subnets there are never offered to it.
_DS_UNSUPPORTED_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}

CHECK = "share-directory-already-shared-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-sharing a directory with an account it is already shared with raises
    DirectoryAlreadySharedException, and the share list is not duplicated.
    """
    directory_id = _create_microsoft_ad(ctx)
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    ds = ctx.client("ds")
    # A syntactically valid 12-digit AWS account id used only as an opaque share target;
    # HANDSHAKE sharing does not validate that the target account actually exists at
    # request time.
    target_account_id = "111122223333"
    ds.share_directory(
        DirectoryId=directory_id,
        ShareMethod="HANDSHAKE",
        ShareTarget={"Id": target_account_id, "Type": "ACCOUNT"},
        ShareNotes="sim2real behavioral check",
    )
    ctx.on_cleanup(lambda: _safe_unshare(ctx, directory_id, target_account_id))

    # Break exactly one thing: share the same directory with the same target again.
    err = _client_error(
        lambda: ds.share_directory(
            DirectoryId=directory_id,
            ShareMethod="HANDSHAKE",
            ShareTarget={"Id": target_account_id, "Type": "ACCOUNT"},
        )
    )
    _assert_error(
        err,
        "DirectoryAlreadySharedException",
        f"Directory {directory_id} is already shared with Account {target_account_id}. : "
        f"RequestId: {_request_id(err)}",
    )

    # Effect absent: exactly one share record for that target, not two.
    shares = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    matching = [s for s in shares if s["SharedAccountId"] == target_account_id]
    assert len(matching) == 1, f"expected exactly 1 share record for {target_account_id}, found {len(matching)}"

    # Positive control: sharing the same directory with a genuinely different target
    # account succeeds.
    other_target_account_id = "444455556666"
    ds.share_directory(
        DirectoryId=directory_id,
        ShareMethod="HANDSHAKE",
        ShareTarget={"Id": other_target_account_id, "Type": "ACCOUNT"},
    )
    ctx.on_cleanup(lambda: _safe_unshare(ctx, directory_id, other_target_account_id))
    shares_after = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert any(s["SharedAccountId"] == other_target_account_id for s in shares_after)


def _client_error(fn):
    """Call fn() and return the refusal's response; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _request_id(err) -> str:
    return err.get("ResponseMetadata", {}).get("RequestId", "")


def _assert_error(err, code, message) -> None:
    got_code = err.get("Error", {}).get("Code")
    got_message = err.get("Error", {}).get("Message")
    assert got_code == code, f"expected {code}, got {got_code!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _default_vpc_two_azs(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnets = sorted((s for s in subnets if s["AvailabilityZone"] not in _DS_UNSUPPORTED_AZS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("need subnets in at least 2 distinct AZs to create a test directory")
    azs = sorted(by_az)
    return vpc_id, [by_az[azs[0]], by_az[azs[1]]]


def _create_microsoft_ad(ctx, password="Sim2Real-TestPW1"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _default_vpc_two_azs(ctx)
    name = ctx.unique_name("sim2real-msad-") + ".test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=password,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ctx, directory_id))
    return directory_id


def _safe_delete_directory(ctx, directory_id):
    """Delete the directory and wait until it is gone; the helper waits out the asynchronous
    unshares that block DeleteDirectory."""
    _delete_directory_and_wait(ctx.client("ds"), directory_id)


def _safe_unshare(ctx, directory_id, target_account_id):
    ds = ctx.client("ds")
    try:
        ds.unshare_directory(
            DirectoryId=directory_id, UnshareTarget={"Id": target_account_id, "Type": "ACCOUNT"}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _directory_stage(ctx, directory_id):
    ds = ctx.client("ds")
    resp = ds.describe_directories(DirectoryIds=[directory_id])
    descs = resp["DirectoryDescriptions"]
    return descs[0]["Stage"] if descs else None


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=2700, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _directory_stage(ctx, directory_id)
        if last in target_stages:
            return last
        if last in ("Failed", "Impaired", "Inoperable") and last not in target_stages:
            raise AssertionError(f"directory {directory_id} reached unexpected stage {last}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={last})"
    )



def _delete_directory_and_wait(ds, directory_id, timeout_s=1500.0, interval_s=30.0):
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
                except ClientError:
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
