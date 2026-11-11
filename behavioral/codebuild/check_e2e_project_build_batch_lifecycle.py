"""e2e-project-build-batch-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-project-build-batch-lifecycle"
GROUP = "e2e"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartBuildBatch->ListBuildBatchesForProject->StopBuildBatch->DeleteBuildBatch removes
    the batch from subsequent ListBuildBatchesForProject calls for the project."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_service_role(ctx, extra_statements=[])
    project_name = ctx.unique_name("sim2real-cb-batch-")

    buildspec = (
        "version: 0.2\n"
        "batch:\n"
        "  fast-fail: false\n"
        "  build-list:\n"
        "    - identifier: build1\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - echo hello-from-batch\n"
        "      - sleep 180\n"
    )

    _create_project_with_retry(
        ctx,
        codebuild,
        {
            "name": project_name,
            "source": {"type": "NO_SOURCE", "buildspec": buildspec},
            "artifacts": {"type": "NO_ARTIFACTS"},
            "environment": {
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux-x86_64-standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            "serviceRole": role_arn,
            "buildBatchConfig": {"serviceRole": role_arn},
            "tags": [{"key": "sim2real", "value": CHECK}],
        },
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    batch = codebuild.start_build_batch(projectName=project_name)["buildBatch"]
    batch_id = batch["id"]

    def _safe_cleanup_batch() -> None:
        try:
            codebuild.stop_build_batch(id=batch_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]:
            _retry_delete_build_batch(codebuild, batch_id, timeout_s=180.0, interval_s=2.0)

    ctx.on_cleanup(_safe_cleanup_batch)

    ids = codebuild.list_build_batches_for_project(projectName=project_name)["ids"]
    assert batch_id in ids, f"expected {batch_id} in ListBuildBatchesForProject right after start"

    codebuild.stop_build_batch(id=batch_id)

    final_status = _poll_until(
        lambda: codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"][0][
            "buildBatchStatus"
        ],
        lambda status: status in ("STOPPED", "SUCCEEDED", "FAILED", "FAULT", "TIMED_OUT"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert final_status == "STOPPED", f"expected batch to end up STOPPED, got {final_status}"

    delete_resp = _retry_delete_build_batch(codebuild, batch_id, timeout_s=180.0)
    assert not delete_resp.get("buildsNotDeleted"), (
        f"expected all underlying builds deleted, got {delete_resp.get('buildsNotDeleted')}"
    )
    # If the batch was stopped before any sub-build actually started, there may be zero
    # underlying builds to delete -- the important invariant is no failed deletions above.

    ids_after = codebuild.list_build_batches_for_project(projectName=project_name)["ids"]
    assert batch_id not in ids_after, "deleted batch still appears in ListBuildBatchesForProject"

    get_after = codebuild.batch_get_build_batches(ids=[batch_id])
    assert get_after["buildBatches"] == [], (
        f"expected no buildBatches for deleted id {batch_id!r}, got {get_after['buildBatches']}"
    )
    # BatchGetBuildBatches echoes buildBatchesNotFound entries as the full batch ARN, not
    # the bare id passed in -- confirmed against real AWS.
    not_found = get_after["buildBatchesNotFound"]
    assert any(entry == batch_id or entry.endswith(f"/{batch_id}") for entry in not_found), (
        f"expected {batch_id!r} in buildBatchesNotFound after delete, got {not_found!r}"
    )


# ===== helpers =====

def _create_service_role(ctx, extra_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ]
    if extra_statements:
        statements.extend(extra_statements)
    policy_name = "sim2real-cb-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_project_with_retry(ctx, codebuild, params, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(**params)["project"]
        except codebuild.exceptions.InvalidInputException as exc:
            last_err = exc
            time.sleep(3.0)
    raise AssertionError(f"CreateProject never succeeded (likely IAM propagation): {last_err}")


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true, last value={value!r}")


def _retry_delete_build_batch(codebuild, batch_id: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> dict:
    """DeleteBuildBatch can transiently reject with InvalidInputException just after the
    batch reports STOPPED, while the last underlying build is still finalizing; retry."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return codebuild.delete_build_batch(id=batch_id)
        except codebuild.exceptions.InvalidInputException as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"DeleteBuildBatch never succeeded: {last_err}")



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
