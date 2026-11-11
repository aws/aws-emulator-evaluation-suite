"""build-batch-environment-variables-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "build-batch-environment-variables-preserved"
GROUP = "representation"
SERVICES = ["codebuild"]

_IMAGE = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
_BATCH_SPEC = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - echo batch-env-check\n"
    "batch:\n"
    "  build-list:\n"
    "    - identifier: build1\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Environment variables with empty, unicode, PLAINTEXT and PARAMETER_STORE values set on
    StartBuildBatch come back from BatchGetBuildBatches with byte-identical name/value/type."""
    codebuild = ctx.client("codebuild")
    ssm = ctx.client("ssm")

    param_name = ctx.unique_name("/sim2real-cb/param-")
    ssm.put_parameter(
        Name=param_name,
        Value="unused-value",
        Type="String",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))

    role_arn = _create_service_role(ctx, extra_actions=["ssm:GetParameters"])

    project_name = ctx.unique_name("sim2real-cb-proj-")
    _create_project_with_retry(
        codebuild,
        name=project_name,
        source={"type": "NO_SOURCE", "buildspec": _BATCH_SPEC},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": _IMAGE,
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    env_vars = [
        {"name": "EMPTY_VAR", "value": "", "type": "PLAINTEXT"},
        {"name": "UNICODE_VAR", "value": "héllo-世界-🚀", "type": "PLAINTEXT"},
        {"name": "PARAM_VAR", "value": param_name, "type": "PARAMETER_STORE"},
    ]

    start_resp = codebuild.start_build_batch(
        projectName=project_name,
        buildspecOverride=_BATCH_SPEC,
        environmentVariablesOverride=env_vars,
        buildBatchConfigOverride={"serviceRole": role_arn},
    )
    batch_id = start_resp["buildBatch"]["id"]
    # Registered before the deliberate stop/poll/delete below runs, so a batch that survives
    # an early assertion failure still gets a best-effort delete attempt.
    ctx.on_cleanup(lambda: _safe_delete_batch(codebuild, batch_id))

    try:
        fetched = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"][0]
        stored_env_vars = fetched["environment"]["environmentVariables"]
        # The list is not order-preserving (PARAMETER_STORE can come before PLAINTEXT entries).
        stored_sorted = sorted((v["name"], v["value"], v["type"]) for v in stored_env_vars)
        expected_sorted = sorted((v["name"], v["value"], v["type"]) for v in env_vars)
        assert stored_sorted == expected_sorted, (
            f"environment variables were not preserved byte-identically: "
            f"{stored_sorted!r} != {expected_sorted!r}"
        )
    finally:
        # Deliberately run inside the check body (300s budget), not ctx.on_cleanup (60s
        # budget): stop + poll-to-terminal + delete for a real batch build can exceed 60s,
        # which would silently abandon the delete and leak the batch.
        batches = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]
        if batches and batches[0]["buildBatchStatus"] == "IN_PROGRESS":
            codebuild.stop_build_batch(id=batch_id)
        _poll_batch_terminal(ctx, batch_id)
        _delete_batch_with_retry(codebuild, batch_id)


# ===== helpers =====
def _create_project_with_retry(codebuild, timeout_s: float = 90.0, **kwargs):
    """CreateProject can transiently fail with InvalidInputException while the freshly
    created IAM service role has not yet propagated; retry within a bounded window."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(**kwargs)["project"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "InvalidInputException" and "role" in message.lower():
                last_exc = exc
                time.sleep(5)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _safe_delete_batch(codebuild, batch_id: str) -> None:
    """Teardown: returns once the batch is gone; a delete that keeps failing raises."""
    batches = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]
    if not batches:
        return
    if batches[0]["buildBatchStatus"] == "IN_PROGRESS":
        codebuild.stop_build_batch(id=batch_id)
    _delete_batch_with_retry(codebuild, batch_id)


def _delete_batch_with_retry(codebuild, batch_id: str, timeout_s: float = 120.0) -> None:
    """buildBatchStatus can flip to a terminal value (e.g. STOPPED) before CodeBuild
    considers the batch fully complete and deletable; a delete issued in that window fails
    with InvalidInputException ("still in progress"). Retry within a bounded window."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            codebuild.delete_build_batch(id=batch_id)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInputException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _poll_batch_terminal(ctx, batch_id: str, timeout_s: float = 90.0) -> None:
    codebuild = ctx.client("codebuild")
    terminal = {"SUCCEEDED", "FAILED", "FAULT", "TIMED_OUT", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        batches = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]
        if not batches or batches[0]["buildBatchStatus"] in terminal:
            return
        time.sleep(3)


def _create_service_role(ctx, extra_actions: list[str] | None = None) -> str:
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
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    actions = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    if extra_actions:
        actions.extend(extra_actions)
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-cb-inline",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-inline")
    )
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
