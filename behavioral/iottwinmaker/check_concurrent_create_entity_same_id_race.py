"""concurrent-create-entity-same-id-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-entity-same-id-race"
GROUP = "concurrency"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateEntity calls racing on the same entityId: exactly one wins, the rest get
    ConflictException, and the entity ends up existing exactly once."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    entity_id = ctx.unique_name("sim2real-race-entity-")
    racer_count = 6

    def _attempt(i):
        try:
            tm.create_entity(
                workspaceId=workspace_id,
                entityId=entity_id,
                entityName=f"racer-{i}",
            )
            return ("ok", i)
        except botocore.exceptions.ClientError as exc:
            return ("error", exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_attempt, range(racer_count)))
    ctx.on_cleanup(lambda: _delete_entity_and_wait(tm, workspace_id, entity_id))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    assert all(code == "ConflictException" for _, code, _msg in failures), failures
    # A loser refused by the entity layer names the entity and workspace; one refused by the
    # resource layer names the entity ARN, so only its stable suffix is asserted.
    expected = f"Entity {entity_id} in workspace {workspace_id} already exists."
    for _, _code, msg in failures:
        if msg.startswith("Entity "):
            assert msg == expected, f"expected message {expected!r}, got {failures}"
        else:
            assert msg.startswith("Resource arn:") and msg.endswith(" already exists."), failures

    # the winning racer is only known via this side channel (which create_entity call didn't
    # raise); it differs from run to run.
    winner_index = successes[0][1]
    final = _wait_entity_state(ctx, workspace_id, entity_id, {"ACTIVE", "ERROR"})
    assert final["status"]["state"] == "ACTIVE", final["status"]
    assert final["entityName"] == f"racer-{winner_index}", final


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
    ctx.on_cleanup(lambda: tm.delete_workspace(workspaceId=workspace_id))
    return workspace_id, role_arn, bucket_name


def _entity_state(tm, workspace_id, entity_id):
    try:
        return tm.get_entity(workspaceId=workspace_id, entityId=entity_id)["status"]["state"]
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _delete_entity_and_wait(tm, workspace_id, entity_id, timeout_s=120.0):
    """Delete the entity and wait until it is gone, so the workspace delete after it succeeds."""
    deadline = time.monotonic() + timeout_s
    while _entity_state(tm, workspace_id, entity_id) in ("CREATING", "UPDATING"):
        if time.monotonic() > deadline:
            raise AssertionError(f"entity {entity_id} never left CREATING/UPDATING")
        time.sleep(2)
    if _entity_state(tm, workspace_id, entity_id) not in (None, "DELETING"):
        tm.delete_entity(workspaceId=workspace_id, entityId=entity_id, isRecursive=True)
    while _entity_state(tm, workspace_id, entity_id) is not None:
        if time.monotonic() > deadline:
            raise AssertionError(f"entity {entity_id} was never removed")
        time.sleep(2)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
