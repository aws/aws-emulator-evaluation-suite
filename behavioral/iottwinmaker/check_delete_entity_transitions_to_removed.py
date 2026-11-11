"""delete-entity-transitions-to-removed."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-entity-transitions-to-removed"
GROUP = "state-machine"
SERVICES = ["iottwinmaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteEntity moves an ACTIVE entity through DELETING until GetEntity/ListEntities no longer see
    it, and a second DeleteEntity on the same id then fails as not-found rather than succeeding again."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    entity_name = ctx.unique_name("sim2real-entity-")
    entity_id = tm.create_entity(
        workspaceId=workspace_id, entityName=entity_name, tags={"sim2real": CHECK}
    )["entityId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=entity_id)))
    _wait_entity_state(ctx, workspace_id, entity_id, {"ACTIVE", "ERROR"})

    delete_resp = tm.delete_entity(workspaceId=workspace_id, entityId=entity_id)
    assert delete_resp["state"] in ("DELETING", "ACTIVE"), f"DeleteEntity returned state={delete_resp['state']!r}"

    _wait_entity_removed(ctx, workspace_id, entity_id)

    listed_ids = set()
    next_token = None
    while True:
        kwargs = {"workspaceId": workspace_id}
        if next_token:
            kwargs["nextToken"] = next_token
        page = tm.list_entities(**kwargs)
        listed_ids.update(summary["entityId"] for summary in page["entitySummaries"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert entity_id not in listed_ids, f"deleted entity {entity_id} still visible in ListEntities: {listed_ids}"

    # Gone means unusable, not just absent from reads — a second delete on the same
    # id must fail the same way a delete on an id that never existed would.
    err = _client_error(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=entity_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"double-delete of removed entity {entity_id} returned {err!r}, want ResourceNotFoundException"
    )
    expected_message = f"Entity {entity_id} in workspace {workspace_id} not found."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"


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
    # S3's own CreateBucket API rejects an explicit LocationConstraint for us-east-1 specifically;
    # every other region requires one. Not a check-specific region pin.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                tags={"sim2real": CHECK},
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
