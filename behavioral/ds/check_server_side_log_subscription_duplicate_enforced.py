"""server-side-log-subscription-duplicate-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "server-side-log-subscription-duplicate-enforced"
GROUP = "server-side"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!Test2024"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """A second CreateLogSubscription on a directory fails with EntityAlreadyExistsException and
    the exact message, leaving the original subscription untouched; after deleting it, creating
    it again succeeds."""
    ds = ctx.client("ds")
    directory_id, _ = _create_simple_ad(ctx)
    log_group_name = _create_log_group_with_ds_policy(ctx, directory_id)

    ds.create_log_subscription(DirectoryId=directory_id, LogGroupName=log_group_name)

    def _delete_sub():
        try:
            ds.delete_log_subscription(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_delete_sub)

    err = _client_error(
        lambda: ds.create_log_subscription(DirectoryId=directory_id, LogGroupName=log_group_name)
    )
    code = err.get("Error", {}).get("Code")
    assert code == "EntityAlreadyExistsException", f"expected EntityAlreadyExistsException, got {code!r}"
    expected_message = (
        f"Log subscription already exists for directory: {directory_id}. : "
        f"RequestId: {_request_id(err)}"
    )
    message = err.get("Error", {}).get("Message")
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    subs = ds.list_log_subscriptions(DirectoryId=directory_id)["LogSubscriptions"]
    assert len(subs) == 1, "the rejected duplicate must not create a second subscription"
    assert subs[0]["LogGroupName"] == log_group_name, (
        f"expected the untouched original subscription to still point at {log_group_name!r}, "
        f"got {subs[0]['LogGroupName']!r}"
    )

    # Positive control: removing and recreating the subscription still works.
    ds.delete_log_subscription(DirectoryId=directory_id)
    subs_after_delete = ds.list_log_subscriptions(DirectoryId=directory_id)["LogSubscriptions"]
    assert subs_after_delete == [], (
        f"expected no log subscriptions after delete, got {subs_after_delete!r}"
    )
    ds.create_log_subscription(DirectoryId=directory_id, LogGroupName=log_group_name)
    subs_after = ds.list_log_subscriptions(DirectoryId=directory_id)["LogSubscriptions"]
    assert len(subs_after) == 1 and subs_after[0]["LogGroupName"] == log_group_name, (
        f"expected exactly one subscription pointing at {log_group_name!r} after recreating, "
        f"got {subs_after!r}"
    )


def _client_error(fn):
    """Call fn() and return the refusal's response; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _request_id(err) -> str:
    return err.get("ResponseMetadata", {}).get("RequestId", "")


def _pick_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for sn in subnets:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
        if len(by_az) >= 2:
            # The lowest-lettered zones: Directory Service refuses a subnet in some zones
            # (for example the fourth zone of us-west-2), and describe order is arbitrary.
            return vpc["VpcId"], [by_az[zone] for zone in sorted(by_az)][:2]
    raise AssertionError("no VPC with subnets in >=2 availability zones to provision a DS directory")


def _wait_directory_stage(ctx, directory_id, target_stages, timeout_s=3600, interval_s=20):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory entered terminal failure stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(f"directory did not reach {target_stages} within {timeout_s}s (last={stage})")


def _create_simple_ad(ctx, name_prefix="sim2realds"):
    # Simple AD (create_directory) is "no longer open to new customers" on AWS;
    # create_microsoft_ad has the same Creating -> Active lifecycle.
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _pick_vpc_and_subnets(ctx)
    name = f"{ctx.unique_name(name_prefix)}.test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]

    def _cleanup():
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _wait_directory_stage(ctx, directory_id, {"Active"})
    return directory_id, name


def _create_log_group_with_ds_policy(ctx, directory_id):
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    log_group_name = f"/aws/directoryservice/{ctx.unique_name('sim2realds-logs')}"
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _safe_delete_log_group(ctx, log_group_name))

    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}:*"
    policy_name = ctx.unique_name("sim2realds-logpolicy")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DSLogSubscriptionSim2Real",
                "Effect": "Allow",
                "Principal": {"Service": "ds.amazonaws.com"},
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": log_group_arn,
            }
        ],
    }
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(ctx, policy_name))
    return log_group_name


def _safe_delete_log_group(ctx, log_group_name):
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_resource_policy(ctx, policy_name):
    try:
        ctx.client("logs").delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
