"""stream-file-ordering-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stream-file-ordering-preserved"
GROUP = "ordering"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStream returns a stream's files in the order CreateStream submitted them, not
    re-sorted by fileId."""
    s3 = ctx.client("s3")
    iot = ctx.client("iot")

    bucket = ctx.unique_name("sim2real-iot-stream-").lower()
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})

    keys = [f"chunk-{i}.bin" for i in range(5)]
    for key in keys:
        s3.put_object(Bucket=bucket, Key=key, Body=key.encode("utf-8"))

    role_arn = _create_stream_role(ctx, bucket)

    # fileIds run 4..0 against keys 0..4, so sorting by fileId would reverse the order
    file_ids = list(range(len(keys) - 1, -1, -1))
    files = [
        {"fileId": fid, "s3Location": {"bucket": bucket, "key": key}}
        for fid, key in zip(file_ids, keys)
    ]
    stream_id = ctx.unique_name("sim2real-stream-")
    _create_stream_with_retry(iot, stream_id, files, role_arn)
    ctx.on_cleanup(lambda: iot.delete_stream(streamId=stream_id))

    described_files = iot.describe_stream(streamId=stream_id)["streamInfo"]["files"]
    described_keys = [f["s3Location"]["key"] for f in described_files]
    assert described_keys == keys, (
        f"DescribeStream must preserve submission order (fileId is not sorted-by), "
        f"expected {keys}, got {described_keys}"
    )


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_stream_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-streamrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "iot.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": f"arn:aws:s3:::{bucket}/*",
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-read", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-read"))
    return role["Arn"]


def _create_stream_with_retry(iot, stream_id, files, role_arn, timeout_s=30.0, interval_s=2.0):
    # a freshly created IAM role can take a few seconds to be usable as roleArn
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_stream(streamId=stream_id, files=files, roleArn=role_arn)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
