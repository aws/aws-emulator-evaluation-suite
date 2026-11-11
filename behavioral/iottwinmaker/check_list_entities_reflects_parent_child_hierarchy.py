"""list-entities-reflects-parent-child-hierarchy."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-entities-reflects-parent-child-hierarchy"
GROUP = "data-plane"
SERVICES = ["iottwinmaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A child created with parentEntityId shows up under ListEntities(parentEntityId=parent) and the
    parent's hasChildEntities eventually flips to true."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    parent_id = tm.create_entity(
        workspaceId=workspace_id, entityName=ctx.unique_name("sim2real-parent-")
    )["entityId"]
    ctx.on_cleanup(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=parent_id))
    _wait_entity_state(ctx, workspace_id, parent_id, {"ACTIVE", "ERROR"})

    child_name = ctx.unique_name("sim2real-child-")
    child_id = tm.create_entity(
        workspaceId=workspace_id, entityName=child_name, parentEntityId=parent_id
    )["entityId"]
    ctx.on_cleanup(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=child_id))
    child_final = _wait_entity_state(ctx, workspace_id, child_id, {"ACTIVE", "ERROR"})
    assert child_final["parentEntityId"] == parent_id, (
        f"GetEntity parentEntityId expected {parent_id!r}, got {child_final.get('parentEntityId')!r}"
    )

    _poll_has_child_entities(ctx, workspace_id, parent_id)

    children = []
    next_token = None
    while True:
        kwargs = {"workspaceId": workspace_id, "filters": [{"parentEntityId": parent_id}]}
        if next_token:
            kwargs["nextToken"] = next_token
        page = tm.list_entities(**kwargs)
        children.extend(summary["entityId"] for summary in page["entitySummaries"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert child_id in children, (
        f"ListEntities(parentEntityId={parent_id!r}) expected to include {child_id!r}, got {children!r}"
    )


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
    # us-east-1 is the one region where S3 CreateBucket rejects an explicit LocationConstraint.
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


def _wait_entity_state(ctx, workspace_id, entity_id, target_states, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last = None
    resp = None
    while time.monotonic() < deadline:
        resp = tm.get_entity(workspaceId=workspace_id, entityId=entity_id)
        last = resp.get("status", {}).get("state")
        if last in target_states:
            return resp
        time.sleep(2)
    raise AssertionError(f"entity never reached {target_states}, last state={last}, resp={resp}")


def _poll_has_child_entities(ctx, workspace_id, parent_id, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = tm.get_entity(workspaceId=workspace_id, entityId=parent_id)
        last = resp.get("hasChildEntities")
        if last:
            return
        time.sleep(2)
    raise AssertionError(f"parent hasChildEntities never became true, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
