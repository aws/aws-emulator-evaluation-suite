"""log-subscription-create-delete-visibility."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-subscription-create-delete-visibility"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """CreateLogSubscription lists the log group for the directory in ListLogSubscriptions; after
    DeleteLogSubscription it is gone, a repeat delete fails with EntityDoesNotExistException and AWS's
    exact message, and DescribeEventTopics stays empty."""
    ds = ctx.client("ds")
    logs = ctx.client("logs")
    sts = ctx.client("sts")

    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    log_group_name = f"/aws/directoryservice/{ctx.unique_name('sim2real-ds-lg-')}"
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    account_id = sts.get_caller_identity()["Account"]
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}:*"
    policy_name = ctx.unique_name("sim2real-ds-logpolicy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DSLogSubscription",
            "Effect": "Allow",
            "Principal": {"Service": "ds.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": log_group_arn,
        }],
    }
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_resource_policy(policyName=policy_name)))

    ds.create_log_subscription(DirectoryId=directory_id, LogGroupName=log_group_name)
    ctx.on_cleanup(lambda: _best_effort(lambda: ds.delete_log_subscription(DirectoryId=directory_id)))

    subs = ds.list_log_subscriptions(DirectoryId=directory_id)["LogSubscriptions"]
    assert any(s["LogGroupName"] == log_group_name and s["DirectoryId"] == directory_id for s in subs), (
        f"expected {log_group_name!r} for directory {directory_id} in ListLogSubscriptions, got {subs!r}"
    )

    ds.delete_log_subscription(DirectoryId=directory_id)
    subs_after = ds.list_log_subscriptions(DirectoryId=directory_id)["LogSubscriptions"]
    assert all(s["LogGroupName"] != log_group_name for s in subs_after), (
        f"expected {log_group_name!r} gone from ListLogSubscriptions after delete, still present in {subs_after!r}"
    )

    # the delete already removed the only subscription -- a repeat delete on the
    # subscription-less directory must fail with the specific not-found code,
    # not silently succeed (proves the association is actually gone, not just unlisted).
    code, message, request_id = _client_error(
        lambda: ds.delete_log_subscription(DirectoryId=directory_id)
    )
    assert code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException deleting an already-deleted log subscription, got {code!r}"
    )
    expected = (
        f"Log subscription does not exist for directory: {directory_id}. : RequestId: {request_id}"
    )
    assert message == expected, (
        f"expected the repeat DeleteLogSubscription to refuse with {expected!r}, got {message!r}"
    )

    # log subscriptions never registered an SNS event topic for this directory.
    topics = ds.describe_event_topics(DirectoryId=directory_id)["EventTopics"]
    assert topics == [], f"expected no event topics for {directory_id}, got {topics!r}"


def _ds_password() -> str:
    return "Sim2Real-Behav!9Qx"


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


def _best_effort(fn) -> None:
    """Teardown only: run fn() and tolerate any ClientError (the resource may already be gone)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
            "ResourceNotFoundException",
        ):
            raise


def _tag_spec(rtype: str, name: str) -> list:
    return [{
        "ResourceType": rtype,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    }]


def _create_vpc_with_subnets(ctx, cidr: str = "10.92.0.0/16"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-ds-vpc-"))
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_ec2_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id)))

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
            CidrBlock=f"10.92.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", ctx.unique_name(f"sim2real-ds-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        ctx.on_cleanup(lambda sid=subnet_id: _delete_ec2_retrying(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


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


def _delete_directory_and_wait(ctx, directory_id, timeout_s=1800.0, interval_s=20.0) -> None:
    ds = ctx.client("ds")
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "EntityDoesNotExistException":
            raise AssertionError(f"unexpected error deleting directory: {code}") from exc
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ds.describe_directories(DirectoryIds=[directory_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
                return
            raise
        descs = resp.get("DirectoryDescriptions", [])
        if not descs or descs[0]["Stage"] == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} was not removed/Deleted within {timeout_s}s")


_SHARED_MAD_NAME = "sim2dssharedmad.sim2real.test"
_SHARED_VPC_TAG_NAME = "sim2real-ds-shared-vpc"


def _find_directory_id_by_name(ctx, name):
    ds = ctx.client("ds")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = ds.describe_directories(**kwargs)
        for desc in resp.get("DirectoryDescriptions", []):
            if desc.get("Name") == name and desc.get("Stage") not in ("Deleting", "Deleted"):
                return desc["DirectoryId"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


def _get_or_create_shared_vpc(ctx):
    """Look up the run's shared VPC by tag before creating one, so concurrent checks
    converge on a single VPC instead of each provisioning their own (and blowing the
    per-region VPC quota). No single check deletes it;
    it persists across runs."""
    ec2 = ctx.client("ec2")

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [_SHARED_VPC_TAG_NAME]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    if not vpcs:
        try:
            ec2.create_vpc(
                CidrBlock="10.90.0.0/16",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": _SHARED_VPC_TAG_NAME},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )
        except ClientError:
            pass
        for _ in range(15):
            vpcs = _existing()
            if vpcs:
                break
            time.sleep(2)
    if not vpcs:
        raise AssertionError("failed to create or find the shared sim2real-ds VPC")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids[:2]

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    for i, az in enumerate(azs):
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.90.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": f"{_SHARED_VPC_TAG_NAME}-subnet{i}"},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                continue
            raise
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    return vpc_id, subnet_ids[:2]


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    """Reuse a long-lived shared AWS Managed Microsoft AD directory across checks rather than
    paying the ~20-45 min Active wait per check; no single check deletes it. While the directory is
    still provisioning this raises past a short bound (failing the check for a clean retry), and AWS
    keeps provisioning it between retries."""
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx)
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_ds_password(),
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is None:
                    raise
            else:
                raise
    return _wait_directory_stage(
        ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=200.0, interval_s=10.0
    )["DirectoryId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
