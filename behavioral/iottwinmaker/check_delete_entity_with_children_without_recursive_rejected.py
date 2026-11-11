"""delete-entity-with-children-without-recursive-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-entity-with-children-without-recursive-rejected"
GROUP = "overly-permissive"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEntity on a parent with children fails ValidationException with the exact message unless
    isRecursive=True, and the parent stays ACTIVE; without the child the same call succeeds, and
    isRecursive=True removes a parent and child together."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    parent_id = tm.create_entity(
        workspaceId=workspace_id, entityName=ctx.unique_name("sim2real-parent-")
    )["entityId"]
    ctx.on_cleanup(lambda: _try_delete_entity(ctx, workspace_id, parent_id, recursive=True))
    _wait_entity_state(ctx, workspace_id, parent_id, {"ACTIVE", "ERROR"})

    child_id = tm.create_entity(
        workspaceId=workspace_id, entityName=ctx.unique_name("sim2real-child-"), parentEntityId=parent_id
    )["entityId"]
    ctx.on_cleanup(lambda: _try_delete_entity(ctx, workspace_id, child_id))
    _wait_entity_state(ctx, workspace_id, child_id, {"ACTIVE", "ERROR"})
    _poll_has_child_entities(ctx, workspace_id, parent_id)

    err = _client_error(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=parent_id))
    assert err["Code"] == "ValidationException", f"unexpected error={err!r}"
    expected_message = f"Cannot delete entity {parent_id} in {workspace_id} as it has child entities."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # effect absent: parent is still there, not deleted.
    still_there = tm.get_entity(workspaceId=workspace_id, entityId=parent_id)
    assert still_there["status"]["state"] == "ACTIVE"

    # restore: remove the blocking child with a plain (non-recursive) delete — this only succeeds
    # if a childless entity is deletable without isRecursive at all.
    tm.delete_entity(workspaceId=workspace_id, entityId=child_id)
    _wait_entity_removed(ctx, workspace_id, child_id)

    # identical call: the exact same non-recursive DeleteEntity(parent_id) that was rejected above
    # now succeeds, proving the rejection was keyed on children and not a blanket requirement for
    # isRecursive=True on every delete.
    tm.delete_entity(workspaceId=workspace_id, entityId=parent_id)
    _wait_entity_removed(ctx, workspace_id, parent_id)

    # separate positive control for the cascade path: a fresh parent/child pair, deleted together
    # by a single isRecursive=True call.
    parent2_id = tm.create_entity(
        workspaceId=workspace_id, entityName=ctx.unique_name("sim2real-parent2-")
    )["entityId"]
    ctx.on_cleanup(lambda: _try_delete_entity(ctx, workspace_id, parent2_id, recursive=True))
    _wait_entity_state(ctx, workspace_id, parent2_id, {"ACTIVE", "ERROR"})

    child2_id = tm.create_entity(
        workspaceId=workspace_id, entityName=ctx.unique_name("sim2real-child2-"), parentEntityId=parent2_id
    )["entityId"]
    ctx.on_cleanup(lambda: _try_delete_entity(ctx, workspace_id, child2_id))
    _wait_entity_state(ctx, workspace_id, child2_id, {"ACTIVE", "ERROR"})
    _poll_has_child_entities(ctx, workspace_id, parent2_id)

    tm.delete_entity(workspaceId=workspace_id, entityId=parent2_id, isRecursive=True)
    _wait_entity_removed(ctx, workspace_id, parent2_id)
    _wait_entity_removed(ctx, workspace_id, child2_id)


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
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_workspace(workspaceId=workspace_id)))
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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _is_removed(fn):
    """Poll-time probe for a removal wait: True once the read fails as not-found, False while the
    resource is still readable."""
    try:
        fn()
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _try_delete_entity(ctx, workspace_id, entity_id, recursive=False):
    tm = ctx.client("iottwinmaker")
    _retry_teardown(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=entity_id, isRecursive=recursive))


def _wait_entity_removed(ctx, workspace_id, entity_id, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _is_removed(lambda: tm.get_entity(workspaceId=workspace_id, entityId=entity_id)):
            return
        time.sleep(2)
    raise AssertionError("entity was never fully removed")


def _retry_teardown(fn, timeout_s=180.0):
    """Teardown: retry a delete that AWS refuses while dependent resources are still being
    removed, and tolerate a resource that is already gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ValidationException", "ConflictException") or time.monotonic() > deadline:
                raise
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
