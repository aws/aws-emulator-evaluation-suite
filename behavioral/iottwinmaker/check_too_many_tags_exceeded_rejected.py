"""too-many-tags-exceeded-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "too-many-tags-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource past the 50-tag quota fails ServiceQuotaExceededException with an empty message and persists
    none of the batch; after untagging room, the same batch succeeds."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)
    workspace_arn = tm.get_workspace(workspaceId=workspace_id)["arn"]

    # First batch (40 tags) stays under the per-call/per-resource limit and succeeds.
    first_batch = {f"sim2real-tag-{i}": f"value-{i}" for i in range(40)}
    tm.tag_resource(resourceARN=workspace_arn, tags=first_batch)

    # Second batch (15 more) is itself under the 50-tag-per-call shape limit, but pushes the
    # resource's cumulative total to 55, which AWS rejects.
    second_batch = {f"sim2real-extra-tag-{i}": f"value-{i}" for i in range(15)}
    try:
        tm.tag_resource(resourceARN=workspace_arn, tags=second_batch)
    except botocore.exceptions.ClientError as exc:
        error = exc.response["Error"]
    else:
        raise AssertionError("TagResource past the 50-tag quota succeeded")
    assert error["Code"] == "ServiceQuotaExceededException", f"unexpected code={error['Code']!r}"
    # AWS returns this refusal with no message text.
    assert error["Message"] == "", repr(error["Message"])

    # effect absent: none of the rejected second batch's tags were persisted.
    tags_after_rejection = tm.list_tags_for_resource(resourceARN=workspace_arn)["tags"]
    assert "sim2real-extra-tag-0" not in tags_after_rejection
    assert "sim2real-tag-0" in tags_after_rejection

    # restore: untag enough of the first batch to clear room under the quota, then replay
    # the IDENTICAL call that was just rejected and demand it now succeeds.
    tm.untag_resource(resourceARN=workspace_arn, tagKeys=[f"sim2real-tag-{i}" for i in range(20)])
    tm.tag_resource(resourceARN=workspace_arn, tags=second_batch)
    tags_after_retry = tm.list_tags_for_resource(resourceARN=workspace_arn)["tags"]
    assert tags_after_retry.get("sim2real-extra-tag-0") == "value-0"
    assert tags_after_retry.get("sim2real-extra-tag-14") == "value-14"


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iottwinmaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _s3_policy_document(bucket_name):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetBucket*", "s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                }
            ],
        }
    )


def _delete_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket_name).get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_workspace_role(ctx):
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-tm-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="s3access", PolicyDocument=_s3_policy_document(bucket_name))
    return role_arn, bucket_name


def _create_workspace(ctx):
    tm = ctx.client("iottwinmaker")
    role_arn, bucket_name = _create_workspace_role(ctx)
    workspace_id = ctx.unique_name("sim2real-tm-ws-")
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            tm.create_workspace(workspaceId=workspace_id, s3Location=f"arn:aws:s3:::{bucket_name}", role=role_arn)
            break
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"CreateWorkspace never succeeded (IAM propagation?): {last_exc}")
    ctx.on_cleanup(lambda: tm.delete_workspace(workspaceId=workspace_id))
    return workspace_id, role_arn, bucket_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
