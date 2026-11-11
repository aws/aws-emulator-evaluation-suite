"""start-build-batch-without-batch-config-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "start-build-batch-without-batch-config-rejected"
GROUP = "e2e"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartBuildBatch on a project without buildBatchConfig is InvalidInputException and creates
    no batch; the same call on a project that has one succeeds. Both share one buildspec with no
    `batch:` section, since buildBatchConfig alone is sufficient for StartBuildBatch."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_service_role(ctx)

    no_batch_buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - echo no-batch-section-here\n"
    )

    plain_project = ctx.unique_name("sim2real-cb-noBatch-")
    batch_project = ctx.unique_name("sim2real-cb-hasBatch-")

    _create_project_with_retry(
        ctx,
        codebuild,
        {
            "name": plain_project,
            "source": {"type": "NO_SOURCE", "buildspec": no_batch_buildspec},
            "artifacts": {"type": "NO_ARTIFACTS"},
            "environment": {
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux-x86_64-standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            "serviceRole": role_arn,
            "tags": [{"key": "sim2real", "value": CHECK}],
        },
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=plain_project))

    _create_project_with_retry(
        ctx,
        codebuild,
        {
            "name": batch_project,
            # Identical buildspec to plain_project — no `batch:` section — so the only
            # difference below is buildBatchConfig.
            "source": {"type": "NO_SOURCE", "buildspec": no_batch_buildspec},
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
    ctx.on_cleanup(lambda: codebuild.delete_project(name=batch_project))

    code, message = _client_error(lambda: codebuild.start_build_batch(projectName=plain_project))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    expected = "BatchConfig must be configured on the project to use the BuildBatch feature"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    ids_after_reject = codebuild.list_build_batches_for_project(projectName=plain_project)["ids"]
    assert ids_after_reject == [], "a batch should not have been created for the rejected call"

    # Positive control: only buildBatchConfig differs.
    batch = codebuild.start_build_batch(projectName=batch_project)["buildBatch"]
    batch_id = batch["id"]

    def _cleanup_batch() -> None:
        # Stop a running batch, then retry the delete while CodeBuild still reports it in progress.
        from botocore.exceptions import ClientError

        batches = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]
        if not batches:
            return
        if batches[0]["buildBatchStatus"] == "IN_PROGRESS":
            codebuild.stop_build_batch(id=batch_id)
        deadline = time.monotonic() + 300.0
        while True:
            try:
                codebuild.delete_build_batch(id=batch_id)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup_batch)

    ids_after_accept = codebuild.list_build_batches_for_project(projectName=batch_project)["ids"]
    assert batch_id in ids_after_accept, (
        f"accepted batch {batch_id!r} not visible in list_build_batches_for_project: "
        f"{ids_after_accept!r}"
    )


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-neg-role-")
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

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    }
    policy_name = "sim2real-cb-neg-inline"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
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


def _client_error(fn):
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
