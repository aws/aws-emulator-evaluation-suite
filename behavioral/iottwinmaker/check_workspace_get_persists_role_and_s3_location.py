"""workspace-get-persists-role-and-s3-location."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workspace-get-persists-role-and-s3-location"
GROUP = "control-plane"
SERVICES = ["iottwinmaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetWorkspace returns exactly the role ARN and s3Location that CreateWorkspace was given, and
    once the workspace is deleted, an independent read and an independent mutation on the same id
    both fail with the specific not-found error."""
    tm = ctx.client("iottwinmaker")
    workspace_id, role_arn, bucket_name = _create_workspace(ctx)

    got = tm.get_workspace(workspaceId=workspace_id)
    assert got["workspaceId"] == workspace_id, f"expected workspaceId {workspace_id!r}, got {got['workspaceId']!r}"
    assert got["role"] == role_arn, f"expected role {role_arn!r} persisted, got {got['role']!r}"
    expected_s3_location = f"arn:aws:s3:::{bucket_name}"
    assert got["s3Location"] == expected_s3_location, (
        f"expected s3Location {expected_s3_location!r} persisted, got {got['s3Location']!r}"
    )

    tm.delete_workspace(workspaceId=workspace_id)

    err = _poll_client_error(lambda: tm.get_workspace(workspaceId=workspace_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected GetWorkspace on a deleted workspace to raise ResourceNotFoundException, got {err!r}"
    )
    expected_message = f"Unable to find workspace for id: {workspace_id}"
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    err = _client_error(lambda: tm.update_workspace(workspaceId=workspace_id, description="post-delete-update"))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected UpdateWorkspace on a deleted workspace to raise ResourceNotFoundException, got {err!r}"
    )
    expected_message = f"Workspace with id {ctx.account}|{workspace_id} does not exist."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"


def _client_error(fn):
    try:
        fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("expected a ClientError but the call succeeded")


def _poll_client_error(fn, deadline_s: float = 30.0):
    """DeleteWorkspace's effect on GetWorkspace may lag briefly; retry a success into the expected error."""
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            fn()
        except botocore.exceptions.ClientError as exc:
            return exc.response["Error"]
        time.sleep(2)
    raise AssertionError(f"the call still succeeded {deadline_s}s after the workspace was deleted")


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
    # CreateBucket rejects an explicit LocationConstraint of "us-east-1" (S3 API quirk, not a
    # hardcoded target region — `region` is still ctx.region throughout).
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
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
            tm.create_workspace(
                workspaceId=workspace_id,
                s3Location=f"arn:aws:s3:::{bucket_name}",
                role=role_arn,
                tags={"sim2real-check": CHECK},
            )
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
    ctx.on_cleanup(lambda: _delete_workspace(ctx, workspace_id))
    return workspace_id, role_arn, bucket_name


def _delete_workspace(ctx, workspace_id):
    tm = ctx.client("iottwinmaker")
    try:
        tm.delete_workspace(workspaceId=workspace_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
