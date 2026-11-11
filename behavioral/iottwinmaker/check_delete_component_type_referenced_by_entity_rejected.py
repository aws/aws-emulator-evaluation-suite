"""delete-component-type-referenced-by-entity-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-component-type-referenced-by-entity-rejected"
GROUP = "overly-permissive"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteComponentType on a component type still referenced by a live entity is rejected with
    ValidationException and the component type stays ACTIVE; a second, unreferenced component
    type in the same workspace still deletes successfully."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    referenced_id = ctx.unique_name("sim2real.tm.referenced.")
    tm.create_component_type(workspaceId=workspace_id, componentTypeId=referenced_id, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _delete_component_type_ignore_missing(ctx, workspace_id, referenced_id))
    _wait_component_type_state(ctx, workspace_id, referenced_id, {"ACTIVE", "ERROR"})

    entity_id = tm.create_entity(
        workspaceId=workspace_id,
        entityName=ctx.unique_name("sim2real-entity-"),
        components={"Comp": {"componentTypeId": referenced_id}},
        tags={"sim2real-check": CHECK},
    )["entityId"]
    ctx.on_cleanup(lambda: _delete_entity_ignore_missing(ctx, workspace_id, entity_id))
    _wait_entity_state(ctx, workspace_id, entity_id, {"ACTIVE", "ERROR"})

    err = _assert_rejected(lambda: tm.delete_component_type(workspaceId=workspace_id, componentTypeId=referenced_id))
    assert err["Code"] == "ValidationException", (
        f"expected DeleteComponentType on a component type referenced by a live entity to raise "
        f"ValidationException, got {err!r}"
    )
    expected_message = (
        f"Component type {referenced_id} is being used by entities [{entity_id}], please delete the entities first."
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # effect absent: the referenced component type still exists and is ACTIVE.
    still_there = tm.get_component_type(workspaceId=workspace_id, componentTypeId=referenced_id)
    assert still_there["status"]["state"] == "ACTIVE", (
        f"expected the rejected-delete component type to remain ACTIVE, got {still_there['status']}"
    )

    # restore: remove the referencing entity, then the IDENTICAL DeleteComponentType call must now
    # succeed -- proving the entity reference, not a permanent contract, is what blocked it.
    tm.delete_entity(workspaceId=workspace_id, entityId=entity_id)
    _wait_entity_removed(ctx, workspace_id, entity_id)
    tm.delete_component_type(workspaceId=workspace_id, componentTypeId=referenced_id)
    _wait_component_type_removed(ctx, workspace_id, referenced_id)

    # delete proves gone and unusable: the independent read above and a mutation both fail with
    # the specific not-found error.
    err = _assert_rejected(
        lambda: tm.update_component_type(workspaceId=workspace_id, componentTypeId=referenced_id)
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected UpdateComponentType on a deleted component type to raise ResourceNotFoundException, "
        f"got {err!r}"
    )
    expected_message = f"Cannot find component type {referenced_id} in workspace {workspace_id}."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # positive control: an unreferenced component type in the same workspace deletes fine too.
    unreferenced_id = ctx.unique_name("sim2real.tm.unreferenced.")
    tm.create_component_type(
        workspaceId=workspace_id, componentTypeId=unreferenced_id, tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: _delete_component_type_ignore_missing(ctx, workspace_id, unreferenced_id))
    _wait_component_type_state(ctx, workspace_id, unreferenced_id, {"ACTIVE", "ERROR"})
    tm.delete_component_type(workspaceId=workspace_id, componentTypeId=unreferenced_id)
    _wait_component_type_removed(ctx, workspace_id, unreferenced_id)


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
    # hardcoded target region -- `region` is still ctx.region throughout).
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
    ctx.on_cleanup(lambda: _delete_workspace_ignore_missing(ctx, workspace_id))
    return workspace_id, role_arn, bucket_name


def _delete_workspace_ignore_missing(ctx, workspace_id):
    """Teardown: DeleteWorkspace refuses while entities or component types are still being
    removed, so retry it until they are gone."""
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + 180.0
    while True:
        try:
            tm.delete_workspace(workspaceId=workspace_id)
            return
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() > deadline:
                raise
        time.sleep(3)


def _wait_component_type_state(ctx, workspace_id, component_type_id, target_states, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last = None
    resp = None
    while time.monotonic() < deadline:
        resp = tm.get_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)
        last = resp.get("status", {}).get("state")
        if last in target_states:
            return resp
        time.sleep(2)
    raise AssertionError(f"component type never reached {target_states}, last state={last}, resp={resp}")


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


def _assert_rejected(fn):
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _wait_component_type_removed(ctx, workspace_id, component_type_id, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _is_removed(lambda: tm.get_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)):
            return
        time.sleep(2)
    raise AssertionError("component type was never fully removed")


def _wait_entity_removed(ctx, workspace_id, entity_id, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _is_removed(lambda: tm.get_entity(workspaceId=workspace_id, entityId=entity_id)):
            return
        time.sleep(2)
    raise AssertionError("entity was never fully removed")


def _delete_component_type_ignore_missing(ctx, workspace_id, component_type_id):
    tm = ctx.client("iottwinmaker")
    try:
        tm.delete_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_entity_ignore_missing(ctx, workspace_id, entity_id):
    tm = ctx.client("iottwinmaker")
    try:
        tm.delete_entity(workspaceId=workspace_id, entityId=entity_id)
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
