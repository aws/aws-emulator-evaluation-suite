"""webhook-filter-groups-unicode-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "webhook-filter-groups-unicode-round-trip"
GROUP = "representation"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode webhook filter-group patterns round-trip byte-identically through CreateWebhook and
    BatchGetProjects; UpdateWebhook without a GitHub credential is rejected with no side effect,
    and a delete + recreate with a second unicode set round-trips too."""
    cb = ctx.client("codebuild")

    existing_github_creds = [
        c
        for c in cb.list_source_credentials().get("sourceCredentialsInfos", [])
        if c.get("serverType") == "GITHUB"
    ]
    if existing_github_creds:
        raise AssertionError(
            "this account already has stored GITHUB source credentials "
            f"({existing_github_creds!r}); this check's UpdateWebhook rejection "
            "assertion depends on there being no stored credential for the source "
            "server type, so it cannot safely run against an account that has one"
        )

    role_arn = _create_codebuild_service_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-wh-uni-")

    _create_project_with_retry(
        cb,
        name=project_name,
        source={
            "type": "GITHUB",
            # manualCreation below means CodeBuild never calls out to GitHub, so
            # any public repo URL is fine and no OAuth/PAT connection is required.
            "location": "https://github.com/aws/aws-codebuild-docker-images.git",
        },
        artifacts={"type": "NO_ARTIFACTS"},
        environment=_minimal_environment(),
        serviceRole=role_arn,
        logsConfig={"cloudWatchLogs": {"status": "DISABLED"}, "s3Logs": {"status": "DISABLED"}},
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    filter_groups_v1 = [
        [
            {"type": "EVENT", "pattern": "PUSH", "excludeMatchedPattern": False},
            {
                "type": "HEAD_REF",
                "pattern": "^refs/heads/ünïcödé-ブランチ-.*$",
                "excludeMatchedPattern": False,
            },
        ]
    ]

    created = cb.create_webhook(
        projectName=project_name, manualCreation=True, filterGroups=filter_groups_v1
    )["webhook"]
    ctx.on_cleanup(lambda: _safe_delete_webhook(cb, project_name))
    assert created["filterGroups"] == filter_groups_v1, (
        f"CreateWebhook echo mismatch: {created['filterGroups']!r} != {filter_groups_v1!r}"
    )

    project_v1 = cb.batch_get_projects(names=[project_name])["projects"][0]
    assert project_v1["webhook"]["filterGroups"] == filter_groups_v1, (
        f"BatchGetProjects filterGroups mismatch: "
        f"{project_v1['webhook']['filterGroups']!r} != {filter_groups_v1!r}"
    )

    filter_groups_v2 = [
        [
            {
                "type": "EVENT",
                "pattern": "PUSH,PULL_REQUEST_CREATED",
                "excludeMatchedPattern": False,
            },
            {
                "type": "HEAD_REF",
                "pattern": "^refs/heads/機能-🚀-résumé-.*$",
                "excludeMatchedPattern": True,
            },
        ]
    ]

    # CodeBuild requires a linked GitHub source credential for UpdateWebhook even when the
    # webhook is manualCreation=True and only filterGroups changes.
    code, message = _client_error(
        lambda: cb.update_webhook(projectName=project_name, filterGroups=filter_groups_v2)
    )
    assert code == "ResourceNotFoundException", (
        f"expected UpdateWebhook without a linked source credential to be rejected with "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = "Access token not found in CodeBuild project for server type github"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected UpdateWebhook left the v1 filter groups unchanged.
    project_after_reject = cb.batch_get_projects(names=[project_name])["projects"][0]
    assert project_after_reject["webhook"]["filterGroups"] == filter_groups_v1, (
        "rejected UpdateWebhook mutated the persisted filterGroups: "
        f"{project_after_reject['webhook']['filterGroups']!r} != {filter_groups_v1!r}"
    )

    # Replacing a manually-created webhook's filter groups is done by delete + recreate.
    cb.delete_webhook(projectName=project_name)
    recreated = cb.create_webhook(
        projectName=project_name, manualCreation=True, filterGroups=filter_groups_v2
    )["webhook"]
    assert recreated["filterGroups"] == filter_groups_v2, (
        f"recreated CreateWebhook echo mismatch: {recreated['filterGroups']!r} != {filter_groups_v2!r}"
    )

    project_v2 = cb.batch_get_projects(names=[project_name])["projects"][0]
    assert project_v2["webhook"]["filterGroups"] == filter_groups_v2, (
        f"BatchGetProjects filterGroups mismatch: "
        f"{project_v2['webhook']['filterGroups']!r} != {filter_groups_v2!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_delete_webhook(cb, project_name: str) -> None:
    try:
        cb.delete_webhook(projectName=project_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _minimal_environment() -> dict[str, Any]:
    return {
        "type": "LINUX_CONTAINER",
        "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
        "computeType": "BUILD_GENERAL1_SMALL",
        "imagePullCredentialsType": "CODEBUILD",
    }


def _create_codebuild_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = json.dumps(
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_project_with_retry(cb, timeout_s: float = 40.0, **kwargs):
    """New IAM roles can take a few seconds to be assumable; retry transient rejections."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return cb.create_project(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInputException":
                raise
            last_exc = exc
            time.sleep(3)
    assert last_exc is not None, "retry loop exited without ever attempting create_project"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
