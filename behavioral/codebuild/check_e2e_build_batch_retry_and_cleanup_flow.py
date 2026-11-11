"""e2e-build-batch-retry-and-cleanup-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-build-batch-retry-and-cleanup-flow"
GROUP = "e2e"
SERVICES = ["codebuild"]

_BATCH_BUILDSPEC = """version: 0.2
batch:
  build-list:
    - identifier: build1
      buildspec: |
        version: 0.2
        phases:
          build:
            commands:
              - exit 1
    - identifier: build2
      buildspec: |
        version: 0.2
        phases:
          build:
            commands:
              - exit 1
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Start a build batch that fails, retry it, stop the retried attempt, confirm ListBuildBatchesForProject reflects it, delete it, list goes empty."""
    cb = ctx.client("codebuild")
    role_arn = _create_codebuild_service_role(ctx, extra_statements=[])
    project_name = ctx.unique_name("sim2real-cb-batch-")

    def _create_project():
        return cb.create_project(
            name=project_name,
            source={"type": "NO_SOURCE", "buildspec": _BATCH_BUILDSPEC},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
            buildBatchConfig={
                "serviceRole": role_arn,
                "combineArtifacts": False,
                "timeoutInMins": 30,
            },
            tags=[{"key": "sim2real", "value": CHECK}],
        )

    _retry_role_propagation(_create_project)
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    # build1 is designed to fail (exit 1) so the batch reaches a terminal FAILED
    # state on its own; RetryBuildBatch only accepts a FAILED batch.
    batch1 = _retry_role_propagation(lambda: cb.start_build_batch(projectName=project_name))["buildBatch"]
    batch_id = batch1["id"]

    status1 = _poll_batch_status(ctx, batch_id, {"FAILED", "STOPPED", "SUCCEEDED"}, timeout_s=240.0)
    assert status1 == "FAILED", f"expected batch build to FAIL via exit 1, got {status1}"

    ids_before_retry = _list_all_batches_for_project(ctx, project_name)
    assert batch_id in ids_before_retry, "failed batch missing from ListBuildBatchesForProject"

    # RetryBuildBatch restarts the SAME batch build id in place (unlike RetryBuild,
    # it does not mint a new identifier) -- verify that empirically rather than
    # assuming a new id is minted.
    retried = cb.retry_build_batch(id=batch_id)["buildBatch"]
    assert retried["id"] == batch_id, (
        f"RetryBuildBatch was expected to restart the same batch id in place, "
        f"got a different id: {retried['id']!r} vs {batch_id!r}"
    )
    # Exercise StopBuildBatch on the retried attempt while it is still in flight.
    cb.stop_build_batch(id=batch_id)
    status2 = _poll_batch_status(ctx, batch_id, {"STOPPED", "FAILED", "SUCCEEDED"}, timeout_s=240.0)
    assert status2 in ("STOPPED", "FAILED"), f"expected retried batch to stop or fail, got {status2}"

    ids_after_retry = _list_all_batches_for_project(ctx, project_name)
    assert batch_id in ids_after_retry, "batch missing from ListBuildBatchesForProject after retry+stop"

    # DeleteBuildBatch is refused until the batch is fully complete; wait on the read API.
    # It keeps refusing for a short while after the read API reports the batch complete,
    # and no read op exposes that, so the delete retries only on that exact refusal.
    _poll_batch_complete(ctx, batch_id, timeout_s=180.0)
    deleted = _retry_delete_build_batch(ctx, batch_id)
    # Empirically, DeleteBuildBatch's statusCode signals whether the batch itself was
    # deleted; buildsDeleted/buildsNotDeleted enumerate constituent build ids (which can
    # be empty once those builds have already been individually reaped), so the batch's
    # own removal is verified via statusCode plus the subsequent list-goes-empty check.
    assert deleted.get("statusCode") == "BATCH_DELETED", (
        f"DeleteBuildBatch did not report success for the batch: {deleted}"
    )

    remaining = _list_all_batches_for_project(ctx, project_name)
    assert batch_id not in remaining, f"batch id still listed after DeleteBuildBatch: {remaining}"
    assert remaining == [], f"ListBuildBatchesForProject not empty after deleting the batch: {remaining}"

    # BatchGetBuildBatches is a second, differently-shaped independent read: it must
    # report the id as not-found rather than merely omitting it from a list.
    after_delete = cb.batch_get_build_batches(ids=[batch_id])
    assert after_delete.get("buildBatches", []) == [], (
        f"BatchGetBuildBatches still returned the deleted batch: {after_delete}"
    )
    not_found = after_delete.get("buildBatchesNotFound", [])
    # BatchGetBuildBatches echoes buildBatchesNotFound as the canonical ARN, not the bare
    # id passed in -- measured empirically rather than assumed.
    assert len(not_found) == 1 and not_found[0].endswith(batch_id), (
        f"BatchGetBuildBatches did not report the deleted batch id as not-found: {after_delete}"
    )

    # A mutation on the dead id must also fail -- fitting, since this check's own subject
    # is RetryBuildBatch: the id must not be revivable once deleted.
    retry_code, retry_message = _error(lambda: cb.retry_build_batch(id=batch_id))
    assert retry_code == "ResourceNotFoundException", f"unexpected code: {retry_code}"
    expected_message = f"BuildBatch cannot be found: {batch_id}"
    assert retry_message == expected_message, (
        f"expected message {expected_message!r}, got {retry_message!r}"
    )


def _create_codebuild_service_role(ctx, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ] + extra_statements
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-cb-policy", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-policy"))
    return role["Role"]["Arn"]


def _retry_role_propagation(fn, timeout_s=90.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "InvalidInputException" and (
                "not authorized" in message or "assume" in message.lower()
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _poll_batch_status(ctx, batch_id, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    cb = ctx.client("codebuild")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cb.batch_get_build_batches(ids=[batch_id])
        batches = resp.get("buildBatches", [])
        if batches:
            status = batches[0]["buildBatchStatus"]
            if status in terminal_statuses:
                return status
        time.sleep(interval_s)
    raise AssertionError(f"build batch {batch_id} never reached {terminal_statuses}, last status={status}")


def _list_all_batches_for_project(ctx, project_name):
    cb = ctx.client("codebuild")
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"projectName": project_name}
        if token:
            kwargs["nextToken"] = token
        resp = cb.list_build_batches_for_project(**kwargs)
        ids.extend(resp.get("ids", []))
        token = resp.get("nextToken")
        if not token:
            break
    return ids


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_delete_build_batch(ctx, batch_id, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    cb = ctx.client("codebuild")
    arn = f"arn:aws:codebuild:{ctx.region}:{ctx.account}:build-batch/{batch_id}"
    in_progress = f"Cannot delete BuildBatch {arn}, as it is still in progress"
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cb.delete_build_batch(id=batch_id)
        except ClientError as err:
            if err.response["Error"].get("Message") != in_progress:
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"DeleteBuildBatch still refused after {timeout_s}s: {last_err}")


def _poll_batch_complete(ctx, batch_id, timeout_s=120.0, interval_s=5.0):
    cb = ctx.client("codebuild")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        batches = cb.batch_get_build_batches(ids=[batch_id]).get("buildBatches", [])
        last = batches[0] if batches else None
        if last and last.get("complete"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"build batch {batch_id} never reported complete, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
