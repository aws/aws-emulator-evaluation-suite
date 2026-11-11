"""execute-query-filters-by-entity-name."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-query-filters-by-entity-name"
GROUP = "data-plane"
SERVICES = ["iottwinmaker"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteQuery's PartiQL-style knowledge-graph MATCH/WHERE returns exactly the matching entity."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    target_name = ctx.unique_name("sim2real-target-entity-")
    other_name = ctx.unique_name("sim2real-other-entity-")
    tag = {"sim2real:managed": "true"}
    target_id = tm.create_entity(workspaceId=workspace_id, entityName=target_name, tags=tag)["entityId"]
    ctx.on_cleanup(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=target_id))
    other_id = tm.create_entity(workspaceId=workspace_id, entityName=other_name, tags=tag)["entityId"]
    ctx.on_cleanup(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=other_id))
    _wait_entity_state(ctx, workspace_id, target_id, {"ACTIVE", "ERROR"})
    _wait_entity_state(ctx, workspace_id, other_id, {"ACTIVE", "ERROR"})

    query = f"SELECT entity FROM EntityGraph MATCH (entity) WHERE entity.entityName = '{target_name}'"
    rows = _poll_query_matches(ctx, workspace_id, query, {target_id})
    assert len(rows) == 1, f"expected exactly 1 row for the entityName filter, got {len(rows)}: {rows}"
    matched = rows[0]["rowData"][0]
    assert matched["entityName"] == target_name, f"expected entityName {target_name!r}, got {matched.get('entityName')!r}"
    assert matched["entityId"] == target_id, f"expected entityId {target_id!r}, got {matched.get('entityId')!r}"


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
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint on CreateBucket.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                tags={"sim2real:managed": "true"},
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


def _poll_query_matches(ctx, workspace_id, query_statement, expected_entity_ids, timeout_s=60.0):
    """Poll until the query's result set is exactly `expected_entity_ids` — not merely a
    superset — so a target that ignores the WHERE clause and returns every entity never
    resolves and times out instead of passing on a lucky row order."""
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last_rows = []
    last_ids = set()
    while time.monotonic() < deadline:
        resp = tm.execute_query(workspaceId=workspace_id, queryStatement=query_statement)
        last_rows = resp.get("rows", [])
        last_ids = {row["rowData"][0]["entityId"] for row in last_rows}
        if last_ids == expected_entity_ids:
            return last_rows
        time.sleep(2)
    raise AssertionError(f"expected entityIds {expected_entity_ids}, last saw {last_ids} ({last_rows})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
