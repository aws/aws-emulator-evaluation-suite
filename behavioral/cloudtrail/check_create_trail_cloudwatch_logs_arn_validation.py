"""create-trail-cloudwatch-logs-arn-validation."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _error(fn):
    """Call fn() and return the (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises, so a target that accepts a call real AWS refuses fails loudly
    instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient CloudTrail control-plane errors."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        # us-east-1 is S3's API default: passing a LocationConstraint for it is itself a
        # rejection, so this is S3's own special case, not an assumption about this check's region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_trail(ct, name):
    """Best-effort teardown: stop logging (if on) then delete the trail."""
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _call(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket}
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


_CWL_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_CWL_WRITE = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }],
})


def _ensure_cwl_role(ctx):
    """Provision the IAM role CloudTrail assumes to write into CloudWatch Logs; return its ARN.
    Teardowns are registered right after each create, so LIFO deletes the inline policy first."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-ct-cwlrole-")
    try:
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=_CWL_TRUST)
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
        iam.put_role_policy(RoleName=role, PolicyName="cwl-write", PolicyDocument=_CWL_WRITE)
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName="cwl-write"))
    except Exception as exc:  # noqa: BLE001
        # Nothing about CloudTrail's log-group validation is attributable without the role.
        raise AssertionError(f"cannot provision the CloudTrail CloudWatch Logs role: {exc}") from exc
    return f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:role/{role}"


def _await_group_refusal(ct, name, absent_group, real_role, deadline_s=90.0, interval_s=5.0):
    """Poll for the log-group refusal, retrying only InvalidCloudWatchLogsRoleArnException while
    the just-created role is not yet resolvable by CloudTrail (IAM is eventually consistent)."""
    deadline = time.monotonic() + deadline_s
    while True:
        code, msg = _error(lambda: ct.update_trail(
            Name=name, CloudWatchLogsLogGroupArn=absent_group, CloudWatchLogsRoleArn=real_role))
        if code != "InvalidCloudWatchLogsRoleArnException" or time.monotonic() >= deadline:
            return code, msg
        time.sleep(interval_s)


CHECK = "create-trail-cloudwatch-logs-arn-validation"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudTrail validates a trail's CloudWatch Logs pair before storing it: a missing group, a missing
    role, either half alone, or a malformed group ARN is refused with its exact code and message,
    nothing is stored, CreateTrail leaves no orphan, and a valid pair is accepted and echoed.
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: an ordinary trail, created by this check, with no CWL config.
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    created = _create_trail(ctx, ct, s3, name)
    minted_arn = created["TrailARN"]
    assert minted_arn.endswith(f":trail/{name}"), minted_arn
    assert "CloudWatchLogsLogGroupArn" not in created, created.get("CloudWatchLogsLogGroupArn")

    # In-account, in-region ARNs that name nothing reach CloudTrail; an out-of-account ARN would be
    # refused by IAM with a 403 instead.
    absent_group = f"arn:aws:logs:{ctx.region}:{account}:log-group:{ctx.unique_name('sim2real-behav-ct-lg-')}:*"
    # A REAL role, created by this check: CloudTrail validates the role half FIRST, so a fake
    # role ARN would break two things at once and pin the wrong refusal.
    real_role = _ensure_cwl_role(ctx)

    def assert_no_cwl_config():
        """GetTrail must report neither half of the CloudWatch Logs configuration."""
        trail = _call(lambda: ct.get_trail(Name=name))["Trail"]
        assert trail["TrailARN"] == minted_arn, trail["TrailARN"]
        assert "CloudWatchLogsLogGroupArn" not in trail, trail.get("CloudWatchLogsLogGroupArn")
        assert "CloudWatchLogsRoleArn" not in trail, trail.get("CloudWatchLogsRoleArn")
        return trail

    assert_no_cwl_config()

    # Break exactly one thing: a log group that does not exist. The role is real and the
    # "both or neither" rule is satisfied, so the group is the ONLY thing at fault. Bounded-retry
    # this first use of the role: IAM is eventually consistent, so an immediate call can still see
    # InvalidCloudWatchLogsRoleArnException even though the role is genuinely valid.
    code, msg = _await_group_refusal(ct, name, absent_group, real_role)
    assert code == "InvalidCloudWatchLogsLogGroupArnException", code
    assert msg == "You must specify an existing log group.", msg
    # Effect absent: the refused update stored nothing.
    assert_no_cwl_config()

    # A well-formed role ARN that names nothing is refused on the ROLE, proving the
    # ordering above: this is the only difference from the call that just ran.
    absent_role = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-ct-role-')}"
    code, msg = _error(
        lambda: ct.update_trail(
            Name=name,
            CloudWatchLogsLogGroupArn=absent_group,
            CloudWatchLogsRoleArn=absent_role,
        )
    )
    assert code == "InvalidCloudWatchLogsRoleArnException", code
    assert msg == "Access denied. Verify in IAM that the role has adequate trust relationships.", msg
    assert_no_cwl_config()

    # Break a different single thing: the group without its companion role. AWS names the
    # ABSENT half — the role — not a parameter-combination error.
    code, msg = _error(
        lambda: ct.update_trail(Name=name, CloudWatchLogsLogGroupArn=absent_group)
    )
    assert code == "InvalidCloudWatchLogsRoleArnException", code
    assert msg == "You must specify a log group and a role ARN.", msg
    assert_no_cwl_config()

    # And a role without its companion group: symmetrically, the absent GROUP is named.
    code, msg = _error(
        lambda: ct.update_trail(Name=name, CloudWatchLogsRoleArn=real_role)
    )
    assert code == "InvalidCloudWatchLogsLogGroupArnException", code
    assert msg == "You must specify a log group and a role ARN.", msg
    assert_no_cwl_config()

    # A syntactically malformed log-group ARN is refused as an ARN, not stored verbatim.
    code, msg = _error(
        lambda: ct.update_trail(
            Name=name,
            CloudWatchLogsLogGroupArn="not-an-arn",
            CloudWatchLogsRoleArn=real_role,
        )
    )
    assert code == "InvalidCloudWatchLogsLogGroupArnException", code
    assert msg == "CloudTrail cannot validate the specified log group ARN.", msg
    assert_no_cwl_config()

    # CreateTrail applies the same validation, and must not leave an orphan trail behind.
    orphan = ctx.unique_name("sim2real-behav-ct-trail-")
    bucket = _call(lambda: ct.get_trail(Name=name))["Trail"]["S3BucketName"]
    code, msg = _error(
        lambda: ct.create_trail(
            Name=orphan,
            S3BucketName=bucket,
            CloudWatchLogsLogGroupArn=absent_group,
            CloudWatchLogsRoleArn=real_role,
        )
    )
    assert code == "InvalidCloudWatchLogsLogGroupArnException", code
    assert msg == "You must specify an existing log group.", msg
    orphan_get_code, orphan_get_msg = _error(lambda: ct.get_trail(Name=orphan))
    assert orphan_get_code == "TrailNotFoundException", orphan_get_code
    assert orphan_get_msg == f"Unknown trail: {orphan} for the user: {account}", orphan_get_msg
    listed = _call(lambda: ct.describe_trails(trailNameList=[orphan]))["trailList"]
    assert listed == [], listed

    # Control case still works: an unrelated field on the minted trail still updates.
    updated = _call(lambda: ct.update_trail(Name=name, S3KeyPrefix="cwl-validation"))
    assert updated["TrailARN"] == minted_arn, updated["TrailARN"]
    prefix = _call(lambda: ct.get_trail(Name=name))["Trail"]["S3KeyPrefix"]
    assert prefix == "cwl-validation", prefix

    # Positive control for the whole surface: an EXISTING log group with the real role is
    # accepted and echoed back on both UpdateTrail and GetTrail. Without this every
    # assertion above would also hold on an emulator that refuses the pair unconditionally.
    group_name = ctx.unique_name("sim2real-behav-ct-lg-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    real_group = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group_name}:*"
    accepted = _call(lambda: ct.update_trail(
        Name=name, CloudWatchLogsLogGroupArn=real_group, CloudWatchLogsRoleArn=real_role))
    assert accepted["CloudWatchLogsLogGroupArn"] == real_group, accepted
    assert accepted["CloudWatchLogsRoleArn"] == real_role, accepted
    stored = _call(lambda: ct.get_trail(Name=name))["Trail"]
    assert stored["CloudWatchLogsLogGroupArn"] == real_group, stored
    assert stored["CloudWatchLogsRoleArn"] == real_role, stored


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
