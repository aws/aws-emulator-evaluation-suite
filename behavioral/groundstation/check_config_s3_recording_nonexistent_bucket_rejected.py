"""config-s3-recording-nonexistent-bucket-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "config-s3-recording-nonexistent-bucket-rejected"
GROUP = "overly-permissive"
SERVICES = ["groundstation"]


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _empty_and_delete_bucket(s3, bucket):
    """Delete the bucket, first removing the access-check object Ground Station writes into it."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfig for an S3RecordingConfig on a real bucket succeeds, while one on a bucket that
    does not exist raises InvalidParameterException with the exact message and lists no config.
    """
    gs = ctx.client("groundstation")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    region = s3.meta.region_name

    bucket_name = ("aws-groundstation-" + ctx.unique_name("sim2real-gs-s3rec-")).lower()
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )

    role_name = ctx.unique_name("sim2real-gs-s3role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "groundstation.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "ArnLike": {"aws:SourceArn": "arn:aws:groundstation:*:*:config/s3-recording/*"}
                    },
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    access_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetBucketLocation", "s3:PutObject", "s3:ListBucket"],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                }
            ],
        }
    )
    policy_name = ctx.unique_name("sim2real-gs-s3pol-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=access_policy)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    good_name = ctx.unique_name("sim2real-gs-s3rec-good-")
    good = None
    last_err = None
    for attempt in range(10):
        try:
            good = gs.create_config(
                name=good_name,
                configData={
                    "s3RecordingConfig": {
                        "bucketArn": f"arn:aws:s3:::{bucket_name}",
                        "roleArn": role_arn,
                        "prefix": "sim2real/",
                    }
                },
            )
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            time.sleep(3)
    assert good is not None, f"CreateConfig kept rejecting a real, permissioned bucket: {last_err}"
    ctx.on_cleanup(
        lambda: gs.delete_config(configId=good["configId"], configType=good["configType"])
    )
    assert good["configType"] == "s3-recording", (
        f"expected configType 's3-recording', got {good['configType']!r}"
    )

    bad_bucket = ("aws-groundstation-" + ctx.unique_name("sim2real-gs-s3rec-missing-")).lower()
    bad_name = ctx.unique_name("sim2real-gs-s3rec-bad-")
    refused = _error(
        lambda: gs.create_config(
            name=bad_name,
            configData={
                "s3RecordingConfig": {
                    "bucketArn": f"arn:aws:s3:::{bad_bucket}",
                    "roleArn": role_arn,
                    "prefix": "sim2real/",
                }
            },
        )
    )
    assert refused == (
        "InvalidParameterException",
        "Unable to create new S3 endpoint config - bucket does not exist.",
    ), f"unexpected outcome for nonexistent S3 bucket: {refused!r}"

    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = gs.list_configs(**kwargs)
        for entry in page.get("configList", []):
            assert entry["name"] != bad_name, (
                f"rejected config {bad_name!r} for a nonexistent bucket still appears in list_configs"
            )
        next_token = page.get("nextToken")
        if not next_token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

