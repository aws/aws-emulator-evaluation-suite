"""list-log-subscriptions-returns-inventory."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "list-log-subscriptions-returns-inventory"
GROUP = 'lifecycle'
SERVICES = ['ds']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """ListLogSubscriptions without DirectoryId returns the account-wide inventory: a new
    subscription appears in the unfiltered list and disappears once it is deleted."""
    ds = ctx.client("ds")
    logs = ctx.client("logs")
    sts = ctx.client("sts")

    directory_id = _create_microsoft_ad(ctx)

    log_group_name = f"/aws/directoryservice/{ctx.unique_name('sim2real-ds-inv-')}"
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _delete_ignoring(lambda: logs.delete_log_group(logGroupName=log_group_name), "ResourceNotFoundException"))

    account_id = sts.get_caller_identity()["Account"]
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}:*"
    policy_name = ctx.unique_name("sim2real-ds-inv-logpolicy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DSLogSubscriptionInventory",
            "Effect": "Allow",
            "Principal": {"Service": "ds.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": log_group_arn,
        }],
    }
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_ignoring(lambda: logs.delete_resource_policy(policyName=policy_name), "ResourceNotFoundException"))

    ds.create_log_subscription(DirectoryId=directory_id, LogGroupName=log_group_name)
    ctx.on_cleanup(lambda: _delete_ignoring(lambda: ds.delete_log_subscription(DirectoryId=directory_id), "EntityDoesNotExistException"))

    resp = ds.list_log_subscriptions()
    assert "LogSubscriptions" in resp, resp
    subs = resp["LogSubscriptions"]
    assert isinstance(subs, list), subs
    assert any(
        s.get("DirectoryId") == directory_id and s.get("LogGroupName") == log_group_name for s in subs
    ), f"created subscription for {directory_id}/{log_group_name} missing from unfiltered inventory: {subs}"

    ds.delete_log_subscription(DirectoryId=directory_id)
    subs_after = ds.list_log_subscriptions()["LogSubscriptions"]
    assert not any(
        s.get("DirectoryId") == directory_id and s.get("LogGroupName") == log_group_name for s in subs_after
    ), f"deleted subscription still present in unfiltered inventory: {subs_after}"


# ===== helpers =====

def _delete_ignoring(fn, not_found: str) -> None:
    """Teardown call: done when it succeeds or answers `not_found`; anything else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != not_found:
            raise


def _delete_directory_and_wait(ds, directory_id, timeout_s: float = 1140.0) -> None:
    """Delete the directory and wait until it is gone, so its ENIs leave the subnets the later
    teardowns delete. DeleteDirectory is retried while the directory is still being created."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "EntityDoesNotExistException":
                return
            if code not in ("ClientException", "InvalidParameterException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            descs = ds.describe_directories(DirectoryIds=[directory_id]).get("DirectoryDescriptions", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
                return
            raise
        if not descs or descs[0]["Stage"] == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(2)


def _tag_spec(rtype: str, name: str) -> list:
    return [{
        "ResourceType": rtype,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    }]


def _delete_ec2_retrying(fn, attempts: int = 12, delay_s: float = 15.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("DependencyViolation", "InvalidParameterValue"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    if last_exc:
        raise last_exc


def _create_vpc_with_subnets(ctx, cidr: str = "10.93.0.0/16"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-ds-inv-vpc-"))
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_ec2_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.93.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", ctx.unique_name(f"sim2real-ds-inv-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_ec2_retrying(lambda: ec2.delete_subnet(SubnetId=sid)))
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            raise AssertionError(f"directory {directory_id} vanished from DescribeDirectories while waiting")
        desc = descs[0]
        last_stage = desc["Stage"]
        if last_stage in terminal_ok:
            return desc
        if last_stage in terminal_bad:
            raise AssertionError(f"directory {directory_id} reached {last_stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage={last_stage} after {timeout_s}s")


def _create_microsoft_ad(ctx) -> str:
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2realdsinv')}.test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password="Sim2Real-Behav!9Qx",
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=2700.0, interval_s=30.0)
    return directory_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
