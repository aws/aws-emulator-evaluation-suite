"""webhook-lifecycle-create-update-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "webhook-lifecycle-create-update-delete"
GROUP = "state-machine"
SERVICES = ["codebuild"]

_PUSH_FILTER = [[{"type": "EVENT", "pattern": "PUSH", "excludeMatchedPattern": False}]]
_PR_FILTER = [
    [{"type": "EVENT", "pattern": "PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED", "excludeMatchedPattern": False}]
]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:codebuild-source-credentials")
def run(ctx) -> None:
    """CreateWebhook returns a payloadUrl, UpdateWebhook changes filterGroups but keeps that
    payloadUrl, and after DeleteWebhook a further UpdateWebhook raises ResourceNotFoundException."""
    codebuild = ctx.client("codebuild")

    existing_github_creds = [
        c
        for c in codebuild.list_source_credentials().get("sourceCredentialsInfos", [])
        if c.get("serverType") == "GITHUB"
    ]
    if existing_github_creds:
        raise AssertionError(
            "this account already has stored GITHUB source credentials "
            f"({existing_github_creds!r}); this check imports its own (bogus) GITHUB "
            "credential and cannot safely overwrite a pre-existing real one"
        )

    role_arn = _create_codebuild_role(ctx)

    # manualCreation=True means CodeBuild never calls GitHub, but UpdateWebhook still requires
    # a stored GitHub credential, so a placeholder is imported.
    creds_arn = codebuild.import_source_credentials(
        token="sim2real-placeholder-personal-access-token",
        serverType="GITHUB",
        authType="PERSONAL_ACCESS_TOKEN",
        shouldOverwrite=True,
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_credentials(codebuild, creds_arn))

    project_name = ctx.unique_name("sim2real-cbwebhook-")
    _create_project_with_retry(
        codebuild,
        name=project_name,
        source={"type": "GITHUB", "location": "https://github.com/aws/aws-codebuild-docker-images.git"},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    created = codebuild.create_webhook(
        projectName=project_name, manualCreation=True, filterGroups=_PUSH_FILTER
    )["webhook"]
    ctx.on_cleanup(lambda: _safe_delete_webhook(codebuild, project_name))

    original_payload_url = created["payloadUrl"]
    assert original_payload_url, "CreateWebhook did not return a webhook payloadUrl"
    assert created["filterGroups"] == _PUSH_FILTER, f"unexpected initial filterGroups: {created['filterGroups']}"

    updated = codebuild.update_webhook(projectName=project_name, filterGroups=_PR_FILTER)["webhook"]
    assert updated["filterGroups"] == _PR_FILTER, f"UpdateWebhook did not persist the new filterGroups: {updated['filterGroups']}"

    # UpdateWebhookOutput does not echo payloadUrl/secret, so identity is checked via an
    # independent read.
    project_after_update = codebuild.batch_get_projects(names=[project_name])["projects"][0]["webhook"]
    assert project_after_update["payloadUrl"] == original_payload_url, (
        f"UpdateWebhook changed the webhook's payloadUrl identity: {project_after_update['payloadUrl']!r} "
        f"!= {original_payload_url!r}"
    )
    assert project_after_update["filterGroups"] == _PR_FILTER, (
        f"persisted filterGroups after update differ from what was submitted: {project_after_update['filterGroups']!r}"
    )

    codebuild.delete_webhook(projectName=project_name)

    code, message = _client_error(
        lambda: codebuild.update_webhook(projectName=project_name, filterGroups=_PUSH_FILTER)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Webhook does not exist for this project"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_project_with_retry(codebuild, **params):
    # IAM trust-policy propagation is eventually consistent: CodeBuild's AssumeRole check on a
    # just-created role fails for several seconds, so retry within a bound.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            codebuild.create_project(**params)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise


def _create_codebuild_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
    if extra_statements:
        policy_name = f"{role_name}-extra"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _safe_delete_webhook(codebuild, project_name):
    try:
        codebuild.delete_webhook(projectName=project_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_credentials(codebuild, creds_arn):
    try:
        codebuild.delete_source_credentials(arn=creds_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
