"""webhook-filter-groups-persist."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "webhook-filter-groups-persist"
GROUP = "representation"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:codebuild-source-credentials")
def run(ctx) -> None:
    """Nested webhook filter-group arrays round-trip through CreateWebhook and
    UpdateWebhook without reordering, dropping, or merging entries."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_service_role(ctx)

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

    project_name = ctx.unique_name("sim2real-cb-proj-")
    _create_project_with_retry(
        codebuild,
        name=project_name,
        source={
            "type": "GITHUB",
            "location": "https://github.com/aws/aws-codebuild-docker-images.git",
        },
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    # UpdateWebhook requires *a* stored access token to exist for the source's server
    # type -- even for a filterGroups-only edit of a manually-created webhook -- so
    # import one. It doesn't need to be a token GitHub itself would accept, since this
    # scenario only exercises persistence of the filterGroups structure, not an actual
    # GitHub-side registration.
    import_resp = codebuild.import_source_credentials(
        serverType="GITHUB",
        authType="PERSONAL_ACCESS_TOKEN",
        token="sim2real-invalid-pat-0000000000000000000000000000",
        shouldOverwrite=True,
    )
    cred_arn = import_resp["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_source_credentials(arn=cred_arn))

    initial_groups = [
        [
            {"type": "EVENT", "pattern": "PUSH", "excludeMatchedPattern": False},
            {
                "type": "HEAD_REF",
                "pattern": "^refs/heads/main$",
                "excludeMatchedPattern": False,
            },
        ],
        [
            {
                "type": "EVENT",
                "pattern": "PULL_REQUEST_CREATED",
                "excludeMatchedPattern": False,
            },
            {
                "type": "BASE_REF",
                "pattern": "^refs/heads/develop$",
                "excludeMatchedPattern": True,
            },
        ],
    ]

    try:
        create_resp = codebuild.create_webhook(
            projectName=project_name, manualCreation=True, filterGroups=initial_groups
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "OAuthProviderException":
            raise AssertionError(
                "CreateWebhook rejected with OAuthProviderException even with "
                "manualCreation=True; this account has no GitHub source-provider linkage "
                "at all, which this scenario needs regardless of manual creation"
            )
        raise
    ctx.on_cleanup(lambda: codebuild.delete_webhook(projectName=project_name))

    assert create_resp["webhook"]["filterGroups"] == initial_groups, (
        "CreateWebhook response filterGroups do not match what was submitted: "
        f"{create_resp['webhook']['filterGroups']!r} != {initial_groups!r}"
    )

    stored_groups = codebuild.batch_get_projects(names=[project_name])["projects"][0][
        "webhook"
    ]["filterGroups"]
    assert stored_groups == initial_groups, (
        f"persisted filterGroups differ from what was created: {stored_groups!r}"
    )

    # UpdateWebhook with a different nested structure: different group count, order,
    # and per-group filter count than the original.
    updated_groups = [
        [
            {
                "type": "EVENT",
                "pattern": "PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED",
                "excludeMatchedPattern": False,
            }
        ],
        [
            {"type": "EVENT", "pattern": "PUSH", "excludeMatchedPattern": False},
            {
                "type": "HEAD_REF",
                "pattern": "^refs/heads/release-",
                "excludeMatchedPattern": False,
            },
            {
                "type": "FILE_PATH",
                "pattern": "^src/",
                "excludeMatchedPattern": True,
            },
        ],
    ]
    update_resp = codebuild.update_webhook(
        projectName=project_name, filterGroups=updated_groups
    )
    assert update_resp["webhook"]["filterGroups"] == updated_groups, (
        "UpdateWebhook response filterGroups do not match what was submitted: "
        f"{update_resp['webhook']['filterGroups']!r} != {updated_groups!r}"
    )

    stored_after_update = codebuild.batch_get_projects(names=[project_name])["projects"][0][
        "webhook"
    ]["filterGroups"]
    assert stored_after_update == updated_groups, (
        f"persisted filterGroups after update differ from what was submitted: "
        f"{stored_after_update!r}"
    )
    assert len(stored_after_update) == 2
    assert len(stored_after_update[0]) == 1
    assert len(stored_after_update[1]) == 3


def _create_service_role(ctx) -> str:
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
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-cb-inline",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-inline")
    )
    return role_arn


def _create_project_with_retry(codebuild, timeout_s: float = 90.0, **kwargs):
    """A freshly created role/policy is not always immediately assumable by
    CodeBuild; retry the transient rejection on a bounded deadline instead of
    guessing a fixed propagation delay."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInputException":
                raise
            last_exc = exc
            time.sleep(3.0)
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
