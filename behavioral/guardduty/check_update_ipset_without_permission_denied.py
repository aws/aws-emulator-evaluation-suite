"""update-ipset-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-ipset-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]

_SESSION_NAME = "sim2real-behav-session"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """UpdateIPSet by a principal lacking guardduty:UpdateIPSet fails with AccessDeniedException
    and its exact message and leaves the IPSet unchanged, while the identical call by a permitted
    caller succeeds."""
    gd = ctx.client("guardduty")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]

    detector_id = _get_or_create_detector(ctx, gd)

    bucket = ctx.unique_name("sim2real-behav-gd-ipset-").lower().replace("_", "-")[:63].rstrip("-")
    if ctx.region == "us-east-1":
        # S3 rejects a LocationConstraint of "us-east-1" itself -- the literal here
        # names S3's own region quirk, not a hardcoded target region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    key = "ipset.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"10.0.0.1/32\n")
    ctx.on_cleanup(lambda: _delete_bucket_and_object(s3, bucket, key))
    location = f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}"

    original_name = ctx.unique_name("sim2real-behav-ipset-")
    ip_set_id = gd.create_ip_set(
        DetectorId=detector_id,
        Name=original_name,
        Format="TXT",
        Location=location,
        Activate=False,
    )["IpSetId"]
    ctx.on_cleanup(lambda: gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id))

    # Positive control, before the denial exists: an unrestricted caller's UpdateIPSet
    # applies. Without this, a target that rejects every UpdateIPSet call would be
    # indistinguishable from one that correctly enforces the IAM deny below.
    baseline_name = ctx.unique_name("sim2real-behav-ipset-baseline-")
    gd.update_ip_set(DetectorId=detector_id, IpSetId=ip_set_id, Name=baseline_name)
    baseline = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    assert baseline["Name"] == baseline_name, (
        f"positive-control UpdateIPSet did not apply before the negative: {baseline!r}"
    )

    role = _create_deny_role(ctx, account_id, ["guardduty:UpdateIPSet"])
    restricted_gd = _assume_role_client(ctx, role["role_arn"], "guardduty")

    error = _client_error(
        lambda: restricted_gd.update_ip_set(
            DetectorId=detector_id, IpSetId=ip_set_id, Name="sim2real-should-not-apply"
        )
    )
    assert error["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {error['Code']}"
    )
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role['role_name']}/{_SESSION_NAME} "
        f"is not authorized to perform: guardduty:UpdateIPSet on resource: "
        f"arn:aws:guardduty:{ctx.region}:{account_id}:detector/{detector_id}/ipset/{ip_set_id} "
        "with an explicit deny in an identity-based policy"
    )
    assert error.get("Message") == expected, (
        f"expected message {expected!r}, got {error.get('Message')!r}"
    )

    unchanged = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    assert unchanged["Name"] == baseline_name, "IPSet name changed despite a denied UpdateIPSet call"

    new_name = ctx.unique_name("sim2real-behav-ipset-updated-")
    gd.update_ip_set(DetectorId=detector_id, IpSetId=ip_set_id, Name=new_name)
    updated = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    assert updated["Name"] == new_name, (
        "the identical UpdateIPSet call by a permitted caller must still succeed after the denial"
    )


def _get_or_create_detector(ctx, gd) -> str:
    """GuardDuty allows exactly one detector per account per region; adopt one
    if this account already has it rather than failing on a dirty account."""
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0]
    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _delete_bucket_and_object(s3, bucket, key):
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_deny_role(ctx, account_id, deny_actions):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-gd-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": deny_actions, "Resource": "*"}],
    }
    policy_name = "deny-inline"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return {"role_name": role_name, "role_arn": role_arn}


def _assume_role_client(ctx, role_arn, service):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    raise AssertionError(f"could not assume role {role_arn} in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
