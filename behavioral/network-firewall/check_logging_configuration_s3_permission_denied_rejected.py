"""logging-configuration-s3-permission-denied-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logging-configuration-s3-permission-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["network-firewall"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateLoggingConfiguration to an own-account bucket whose policy denies the caller
    s3:GetBucketPolicy/s3:PutBucketPolicy fails with LogDestinationPermissionException and the exact
    message, attaches no logging configuration, and succeeds once the deny is removed."""
    nfw = ctx.client("network-firewall")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    region = ctx.region
    account_id = sts.get_caller_identity()["Account"]

    fw = _create_basic_firewall(ctx)
    bucket = ctx.unique_name("sim2real-nfw-logs-").lower()
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    # Deny the account itself the ability to read/write the bucket policy. Network Firewall
    # needs those two actions (via the caller's own credentials) to auto-attach the log
    # delivery policy statement when the caller owns the bucket; blocking them makes the
    # auto-attach -- and therefore UpdateLoggingConfiguration -- fail.
    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyBucketPolicyManagement",
            "Effect": "Deny",
            "Principal": {"AWS": account_id},
            "Action": ["s3:PutBucketPolicy", "s3:GetBucketPolicy"],
            "Resource": f"arn:aws:s3:::{bucket}",
        }],
    })
    s3.put_bucket_policy(Bucket=bucket, Policy=deny_policy)
    policy_present = {"deny": True}
    ctx.on_cleanup(lambda: _delete_bucket_policy_ignore_missing(s3, bucket) if policy_present["deny"] else None)

    log_config = {"LogDestinationConfigs": [{
        "LogType": "ALERT", "LogDestinationType": "S3",
        "LogDestination": {"bucketName": bucket},
    }]}
    code, message = _error_code(lambda: nfw.update_logging_configuration(
        FirewallArn=fw["firewall_arn"], LoggingConfiguration=log_config,
    ))
    assert code == "LogDestinationPermissionException", f"expected LogDestinationPermissionException, got {code}"
    assert message == (
        f"Access Denied for LogDestination: {bucket}. Please check LogDestination permission"
    ), f"unexpected refusal message: {message!r}"

    # effect absent: no logging configuration got attached
    current = nfw.describe_logging_configuration(FirewallArn=fw["firewall_arn"])
    current_configs = current.get("LoggingConfiguration", {}).get("LogDestinationConfigs", [])
    assert current_configs == [], (
        f"rejected UpdateLoggingConfiguration must leave no destination attached, got {current_configs!r}"
    )

    # positive control: remove the deny (a distinct s3:DeleteBucketPolicy action, still
    # permitted) and the same call succeeds
    s3.delete_bucket_policy(Bucket=bucket)
    policy_present["deny"] = False
    nfw.update_logging_configuration(FirewallArn=fw["firewall_arn"], LoggingConfiguration=log_config)
    ctx.on_cleanup(lambda: nfw.update_logging_configuration(
        FirewallArn=fw["firewall_arn"], LoggingConfiguration={"LogDestinationConfigs": []},
    ))
    after = nfw.describe_logging_configuration(FirewallArn=fw["firewall_arn"])
    after_bucket = after["LoggingConfiguration"]["LogDestinationConfigs"][0]["LogDestination"]["bucketName"]
    assert after_bucket == bucket, (
        f"removing the deny must let the identical call attach the same bucket, expected {bucket!r} got {after_bucket!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {resp!r}")


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _delete_bucket_policy_ignore_missing(s3, bucket):
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NoSuchBucketPolicy", "NoSuchBucket"):
            raise


def _retry_dependency(fn, timeout_s=180, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "DependencyViolation" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_firewall_policy_when_free(nfw, policy_arn, timeout_s=300, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidOperationException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_basic_firewall(ctx, *, delete_protection=False, subnet_change_protection=False,
                            firewall_policy_change_protection=False, stateful_rule_group_arn=None):
    ec2 = ctx.client("ec2")
    nfw = ctx.client("network-firewall")
    name = ctx.unique_name("sim2real-nfw-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.88.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name + "-subnet"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    policy_doc = {
        "StatelessDefaultActions": ["aws:forward_to_sfe"],
        "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
    }
    if stateful_rule_group_arn:
        policy_doc["StatefulRuleGroupReferences"] = [{"ResourceArn": stateful_rule_group_arn}]
    policy_name = ctx.unique_name("sim2real-nfw-policy-")
    policy_resp = nfw.create_firewall_policy(FirewallPolicyName=policy_name, FirewallPolicy=policy_doc)
    policy_arn = policy_resp["FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: _delete_firewall_policy_when_free(nfw, policy_arn))

    fw_resp = nfw.create_firewall(
        FirewallName=name,
        FirewallPolicyArn=policy_arn,
        VpcId=vpc_id,
        SubnetMappings=[{"SubnetId": subnet_id}],
        DeleteProtection=delete_protection,
        SubnetChangeProtection=subnet_change_protection,
        FirewallPolicyChangeProtection=firewall_policy_change_protection,
    )
    firewall_arn = fw_resp["Firewall"]["FirewallArn"]
    update_token = nfw.describe_firewall(FirewallArn=firewall_arn)["UpdateToken"]

    def _del_firewall():
        try:
            nfw.update_firewall_delete_protection(FirewallArn=firewall_arn, DeleteProtection=False)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            nfw.delete_firewall(FirewallArn=firewall_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        for _ in range(90):
            try:
                nfw.describe_firewall(FirewallArn=firewall_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(5)

    ctx.on_cleanup(_del_firewall)

    return {
        "nfw": nfw, "ec2": ec2, "name": name, "vpc_id": vpc_id, "subnet_id": subnet_id, "az": az,
        "policy_name": policy_name, "policy_arn": policy_arn, "firewall_arn": firewall_arn,
        "update_token": update_token,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
