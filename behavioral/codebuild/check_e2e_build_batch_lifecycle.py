"""e2e-build-batch-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-build-batch-lifecycle"
GROUP = "e2e"
SERVICES = ["codebuild"]
_SCENARIO = "e2e-build-batch-lifecycle"

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                # The batch orchestrator (this same role, via buildBatchConfig.serviceRole)
                # dispatches each sub-build with these calls against the project itself; without
                # them DOWNLOAD_BATCHSPEC fails with CLIENT_ERROR/AccessDeniedException.
                "Effect": "Allow",
                "Action": [
                    "codebuild:StartBuild",
                    "codebuild:StopBuild",
                    "codebuild:RetryBuild",
                    "codebuild:BatchGetBuilds",
                    "codebuild:BatchGetProjects",
                ],
                "Resource": "*",
            },
        ],
    }
)

_BATCH_BUILDSPEC = """version: 0.2
batch:
  fast-fail: false
  build-list:
    - identifier: groupA
    - identifier: groupB
phases:
  build:
    commands:
      - echo running
      - sleep 90
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A build batch appears in ListBuildBatchesForProject while in progress, transitions
    to STOPPED under StopBuildBatch (observed via BatchGetBuildBatches), and disappears
    after DeleteBuildBatch."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-behav-batchproj-")
    _retry_transient_role_error(
        lambda: codebuild.create_project(
            name=project_name,
            source={"type": "NO_SOURCE", "buildspec": _BATCH_BUILDSPEC},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
            buildBatchConfig={"serviceRole": role_arn, "combineArtifacts": False},
            tags=[{"key": "sim2real", "value": _SCENARIO}],
        ),
        timeout_s=120.0,
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    batch_id = _retry_transient_role_error(
        lambda: codebuild.start_build_batch(projectName=project_name)["buildBatch"]["id"],
        timeout_s=120.0,
    )

    ids_in_project = _poll_until(
        lambda: codebuild.list_build_batches_for_project(projectName=project_name)["ids"],
        lambda ids: batch_id in ids,
        timeout_s=60,
        interval_s=3,
    )
    assert batch_id in ids_in_project, f"expected {batch_id} in ListBuildBatchesForProject, got {ids_in_project}"

    def _get_batch() -> dict:
        return codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"][0]

    in_progress = _poll_until(
        _get_batch,
        lambda b: b["currentPhase"] != "SUBMITTED" or b["complete"],
        timeout_s=180,
        interval_s=5,
    )
    assert in_progress["buildBatchStatus"] in ("IN_PROGRESS", "SUCCEEDED"), (
        f"status={in_progress['buildBatchStatus']} phases="
        f"{[(p.get('phaseType'), p.get('phaseStatus'), p.get('contexts')) for p in in_progress.get('phases', [])]}"
    )

    codebuild.stop_build_batch(id=batch_id)
    stopped = _poll_until(
        _get_batch,
        lambda b: b["complete"],
        timeout_s=180,
        interval_s=5,
    )
    assert stopped["buildBatchStatus"] == "STOPPED", f"expected STOPPED, got {stopped}"

    batch_arn = stopped["arn"]
    _retry_delete_build_batch(codebuild, batch_id, timeout_s=180.0)
    after_delete = codebuild.batch_get_build_batches(ids=[batch_id])
    assert after_delete["buildBatches"] == [], f"deleted batch still returned: {after_delete}"
    # BatchGetBuildBatches echoes buildBatchesNotFound entries as the full ARN, not the short id
    # that was passed in as `ids` -- confirmed against real AWS, not assumed.
    assert batch_arn in after_delete["buildBatchesNotFound"], (
        f"expected {batch_arn} in buildBatchesNotFound, got {after_delete['buildBatchesNotFound']}"
    )

    try:
        codebuild.stop_build_batch(id=batch_id)
        raise AssertionError(f"StopBuildBatch on deleted batch {batch_id} did not raise")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException stopping a deleted batch, got {code}: {exc}"
        )
        assert message == f"BuildBatch {batch_id} does not exist", message


def _create_codebuild_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cb-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-logs", PolicyDocument=_ROLE_POLICY)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-logs"))
    return role["Arn"]


def _retry_transient_role_error(call: Any, *, timeout_s: float):
    """IAM trust-policy propagation exposes no condition to poll: both CreateProject and
    StartBuildBatch can synchronously validate that CodeBuild can assume the service role, and
    either can transiently reject a role created moments earlier. Retry only that specific,
    named error, bounded by a deadline, rather than presleeping a fixed guess."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            msg = (err.response.get("Error", {}).get("Message") or "").lower()
            transient_role = code == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg or "service role" in msg
            )
            if not transient_role or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _retry_delete_build_batch(codebuild: Any, batch_id: str, *, timeout_s: float, interval_s: float = 5.0) -> None:
    """DeleteBuildBatch can transiently reject with InvalidInputException just after the batch
    reports STOPPED/complete, while the last underlying sub-build is still finalizing; retry
    bounded by a deadline rather than trusting the first attempt."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            codebuild.delete_build_batch(id=batch_id)
            return
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            msg = (err.response.get("Error", {}).get("Message") or "").lower()
            still_in_progress = code == "InvalidInputException" and "still in progress" in msg
            if not still_in_progress or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
