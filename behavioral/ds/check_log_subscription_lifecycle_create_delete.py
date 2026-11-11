"""log-subscription-lifecycle-create-delete."""
from __future__ import annotations

import itertools
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "log-subscription-lifecycle-create-delete"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """CreateLogSubscription attaches a log group (visible in ListLogSubscriptions) and
    DeleteLogSubscription removes it from the list; a second delete fails with
    EntityDoesNotExistException."""
    logs = ctx.client("logs")
    log_group_name = f"/sim2real/{ctx.unique_name('ds-log-')}"
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _cleanup_log_group(ctx, log_group_name))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_name = ctx.unique_name("ds-log-policy-")
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realDsLogSubscription",
                "Effect": "Allow",
                "Principal": {"Service": "ds.amazonaws.com"},
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}:*",
            }
        ],
    }
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_document))
    ctx.on_cleanup(lambda: _cleanup_resource_policy(ctx, policy_name))

    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    ctx.on_cleanup(lambda: _cleanup_delete_directory(ctx, directory_id))
    desc = _wait_for_directory_stage(ctx, ds, directory_id, {"Active", "Failed"}, timeout_s=2700)
    assert desc["Stage"] == "Active", f"expected Stage=Active, got {desc['Stage']!r} ({desc.get('StageReason')})"

    ds.create_log_subscription(DirectoryId=directory_id, LogGroupName=log_group_name)

    def _cleanup_subscription():
        try:
            ds.delete_log_subscription(DirectoryId=directory_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup_subscription)

    subs = ds.list_log_subscriptions(DirectoryId=directory_id)["LogSubscriptions"]
    assert any(s["LogGroupName"] == log_group_name for s in subs), subs

    ds.delete_log_subscription(DirectoryId=directory_id)
    subs_after = ds.list_log_subscriptions(DirectoryId=directory_id)["LogSubscriptions"]
    assert not any(s["LogGroupName"] == log_group_name for s in subs_after), subs_after

    code, message, request_id = _client_error(lambda: ds.delete_log_subscription(DirectoryId=directory_id))
    assert code == "EntityDoesNotExistException", f"expected EntityDoesNotExistException, got {code!r}"
    expected = f"Log subscription does not exist for directory: {directory_id}. : RequestId: {request_id}"
    assert message == expected, (
        f"expected the repeat DeleteLogSubscription to refuse with {expected!r}, got {message!r}"
    )


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


def _cleanup_log_group(ctx, log_group_name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cleanup_resource_policy(ctx, policy_name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _default_vpc_azs(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in the region to host the directory's network interfaces")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in >=2 availability zones, required by CreateMicrosoftAD")
    return vpc_id, by_az


def _create_microsoft_ad(ctx) -> str:
    # create_directory (Simple AD) is "no longer open to new customers" on real AWS;
    # create_microsoft_ad is the supported equivalent with the same Creating -> Active
    # lifecycle this check depends on.
    ds = ctx.client("ds")
    vpc_id, by_az = _default_vpc_azs(ctx)
    name = ctx.unique_name("sim2realds") + ".test"
    # CreateMicrosoftAD can reject a specific AZ as capacity-constrained for directory
    # infrastructure even though EC2 itself accepts subnets there; try every AZ pair
    # before giving up rather than pinning the first two encountered.
    az_names = list(by_az)
    last_exc = None
    for az_a, az_b in itertools.combinations(az_names, 2):
        try:
            resp = ds.create_microsoft_ad(
                Name=name,
                Password="Sim2Real-Test-Passw0rd!",
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": [by_az[az_a], by_az[az_b]]},
            )
            return resp["DirectoryId"]
        except ClientError as e:
            if "capacity constrained" not in str(e) and "Failed to locate Availability Zone" not in str(e):
                raise
            last_exc = e
    raise AssertionError(f"no pair of default-VPC availability zones could host a directory: {last_exc}")


def _cleanup_delete_directory(ctx, directory_id: str) -> None:
    ds = ctx.client("ds")
    try:
        _delete_directory_and_wait(ds, directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _wait_for_directory_stage(ctx, ds, directory_id: str, targets: set[str], timeout_s: float = 2700.0, interval_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage in targets:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage {last_stage!r} after {timeout_s}s")


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
