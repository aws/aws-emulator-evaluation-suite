"""execute-query-invalid-syntax-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-query-invalid-syntax-rejected"
GROUP = "overly-permissive"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteQuery with a queryStatement that is not valid PartiQL knowledge-graph syntax is
    rejected with ValidationException, while a well-formed query against the same workspace
    still returns results."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    entity_name = ctx.unique_name("sim2real-entity-")
    entity_id = tm.create_entity(workspaceId=workspace_id, entityName=entity_name, tags=_mgmt_tags())["entityId"]

    def _cleanup_entity():
        _retry_teardown(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=entity_id))
        _wait_entity_removed(ctx, workspace_id, entity_id)

    ctx.on_cleanup(_cleanup_entity)
    _wait_entity_state(ctx, workspace_id, entity_id, {"ACTIVE", "ERROR"})

    err = _client_error(
        lambda: tm.execute_query(workspaceId=workspace_id, queryStatement="THIS IS NOT PARTIQL !!! ###")
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected_message = "Invalid QueryStatement: at line 1, column 21: invalid token, token recognition error at: '!!'"
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # positive control: a well-formed query on the same workspace still works.
    valid_query = f"SELECT entity FROM EntityGraph MATCH (entity) WHERE entity.entityName = '{entity_name}'"
    rows = _poll_query(ctx, workspace_id, valid_query, expected_count=1)
    matched_id = rows[0]["rowData"][0]["entityId"]
    assert matched_id == entity_id, f"expected matched entityId {entity_id!r}, got {matched_id!r}"

    # the teardown already deletes this workspace; prove it is actually gone rather than leaving
    # the delete unasserted (its own cleanup lambda's exceptions are swallowed by the harness).
    tm.delete_entity(workspaceId=workspace_id, entityId=entity_id)
    _wait_entity_removed(ctx, workspace_id, entity_id)
    tm.delete_workspace(workspaceId=workspace_id)
    _wait_workspace_removed(ctx, workspace_id)


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-tm"}


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
    # S3 rejects an explicit LocationConstraint for us-east-1 (its own bucket-creation quirk,
    # not a pin of this check to one region).
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]}
    )
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
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
                tags=_mgmt_tags(),
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


def _wait_workspace_removed(ctx, workspace_id, timeout_s=120.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _is_removed(lambda: tm.get_workspace(workspaceId=workspace_id)):
            return
        time.sleep(3)
    raise AssertionError(f"workspace {workspace_id} was never fully removed")


def _client_error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_query(ctx, workspace_id, query_statement, expected_count, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last_rows = []
    while time.monotonic() < deadline:
        resp = tm.execute_query(workspaceId=workspace_id, queryStatement=query_statement)
        last_rows = resp.get("rows", [])
        if len(last_rows) >= expected_count:
            return last_rows
        time.sleep(2)
    raise AssertionError(f"expected {expected_count} rows, got {len(last_rows)}")


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
