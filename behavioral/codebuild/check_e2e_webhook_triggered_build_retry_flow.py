"""e2e-webhook-triggered-build-retry-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-webhook-triggered-build-retry-flow"
GROUP = "e2e"
SERVICES = ["codebuild"]
_SCENARIO = CHECK


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateWebhook + StartBuild + RetryBuild produces a build linked to the original
    (same project, buildNumber+1); after DeleteWebhook the webhook is no longer usable."""
    codebuild = ctx.client("codebuild")
    secretsmanager = ctx.client("secretsmanager")

    # RUNNER_BUILDKITE_BUILD webhooks are the only webhook type CodeBuild supports on a
    # NO_SOURCE project without an OAuth/App connection to a real source provider, since the
    # webhook is never actually registered with a third party (Buildkite webhooks are always
    # created manually) -- see "Setting up a Buildkite runner programmatically" in the guide.
    secret_name = ctx.unique_name("sim2real-cb-bk-token-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString="dummy-agent-token",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    role_arn = _create_service_role(ctx, secret_arn)
    project_name = ctx.unique_name("sim2real-cb-webhook-")

    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - echo build-ok\n"
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
                "environmentVariables": [
                    {
                        "name": "CODEBUILD_CONFIG_BUILDKITE_AGENT_TOKEN",
                        "type": "SECRETS_MANAGER",
                        "value": secret_name,
                    }
                ],
            },
            "serviceRole": role_arn,
            "tags": [{"key": "sim2real", "value": _SCENARIO}],
        },
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    webhook = codebuild.create_webhook(
        projectName=project_name,
        buildType="RUNNER_BUILDKITE_BUILD",
        filterGroups=[[{"type": "EVENT", "pattern": "WORKFLOW_JOB_QUEUED"}]],
    )["webhook"]
    assert webhook.get("payloadUrl"), f"CreateWebhook returned no payloadUrl: {webhook!r}"
    webhook_deleted = False

    def _safe_delete_webhook() -> None:
        if not webhook_deleted:
            _unless_gone(lambda: codebuild.delete_webhook(projectName=project_name))

    ctx.on_cleanup(_safe_delete_webhook)

    build1 = codebuild.start_build(projectName=project_name)["build"]
    build1_id = build1["id"]

    def _safe_stop_build(build_id):
        return lambda: _unless_gone(lambda: codebuild.stop_build(id=build_id))

    ctx.on_cleanup(_safe_stop_build(build1_id))

    build1_final = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build1_id])["builds"][0],
        lambda b: b["buildStatus"] != "IN_PROGRESS",
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert build1_final["buildStatus"] == "SUCCEEDED", (
        f"expected the original build to succeed, got {build1_final['buildStatus']}"
    )

    build2 = codebuild.retry_build(id=build1_id)["build"]
    ctx.on_cleanup(_safe_stop_build(build2["id"]))

    assert build2["id"] != build1_id, (
        f"RetryBuild should mint a new build id, got the original {build1_id!r} back"
    )
    assert build2["projectName"] == project_name == build1_final["projectName"], (
        f"retried build project mismatch: {build2['projectName']!r} vs {project_name!r}"
    )
    assert build2["buildNumber"] == build1_final["buildNumber"] + 1, (
        "RetryBuild's new build should be the next buildNumber after the original"
    )

    # Positive control: update_webhook succeeds against the still-live webhook, so the
    # ResourceNotFoundException asserted below is caused by the delete, not by a call that
    # never worked in the first place. (UpdateWebhook's response never echoes payloadUrl —
    # only CreateWebhook does — so the independent-read anchor here is filterGroups/buildType.)
    webhook_before_delete = codebuild.update_webhook(projectName=project_name)["webhook"]
    assert webhook_before_delete.get("buildType") == webhook["buildType"] == "RUNNER_BUILDKITE_BUILD", (
        f"update_webhook on the live webhook changed buildType: {webhook_before_delete!r}"
    )
    assert webhook_before_delete.get("filterGroups") == webhook["filterGroups"], (
        f"update_webhook on the live webhook should preserve filterGroups: "
        f"before={webhook['filterGroups']!r} after={webhook_before_delete.get('filterGroups')!r}"
    )

    codebuild.delete_webhook(projectName=project_name)
    webhook_deleted = True

    project_after_delete = codebuild.batch_get_projects(names=[project_name])["projects"][0]
    assert project_after_delete.get("webhook") is None, (
        f"expected no webhook on {project_name} after DeleteWebhook, "
        f"got {project_after_delete.get('webhook')!r}"
    )

    code, message = _client_error(lambda: codebuild.update_webhook(projectName=project_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from update_webhook after delete, got {code!r}"
    )
    assert message == "Webhook does not exist for this project", message


# ===== helpers =====

def _unless_gone(fn) -> None:
    """Teardown call: returns when the resource is already gone; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_service_role(ctx, secret_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-wh-role-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": secret_arn,
            },
        ],
    }
    policy_name = "sim2real-cb-wh-inline"
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


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true, last value={value!r}")


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
