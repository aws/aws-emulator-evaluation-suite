"""put-resource-policy-overwrite-last-writer-wins."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-overwrite-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutResourcePolicy call fully replaces the prior policy document (no merge)."""
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(ctx, role_arn, _QUICK_BUILDSPEC)
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    # CodeBuild resource-policy principals must reference a real, resolvable IAM entity in
    # the account (an arbitrary made-up ARN/account id is rejected as "Invalid principal").
    # Use the account root for both writes and rely on Sid/Action divergence (not principal
    # divergence) to prove the second write fully replaces rather than merges with the first.
    principal = f"arn:aws:iam::{account_id}:root"

    projects = codebuild.batch_get_projects(names=[project_name])["projects"]
    project_arn = projects[0]["arn"]
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_resource_policy(resourceArn=project_arn)))

    policy_v1 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FirstWriterStatement",
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": ["codebuild:BatchGetProjects"],
                "Resource": project_arn,
            }
        ],
    }
    codebuild.put_resource_policy(resourceArn=project_arn, policy=json.dumps(policy_v1))
    fetched_v1 = json.loads(codebuild.get_resource_policy(resourceArn=project_arn)["policy"])
    assert len(fetched_v1["Statement"]) == 1, f"expected 1 statement after first write, got {fetched_v1}"
    assert fetched_v1["Statement"][0]["Sid"] == "FirstWriterStatement", (
        f"expected Sid 'FirstWriterStatement', got {fetched_v1['Statement'][0].get('Sid')!r}"
    )
    action_v1 = fetched_v1["Statement"][0]["Action"]
    action_v1 = action_v1 if isinstance(action_v1, list) else [action_v1]
    assert set(action_v1) == {"codebuild:BatchGetProjects"}, (
        f"expected Action {{'codebuild:BatchGetProjects'}}, got {set(action_v1)}"
    )

    policy_v2 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SecondWriterStatement",
                "Effect": "Allow",
                "Principal": {"AWS": principal},
                "Action": [
                    "codebuild:BatchGetProjects",
                    "codebuild:BatchGetBuilds",
                    "codebuild:ListBuildsForProject",
                ],
                "Resource": project_arn,
            }
        ],
    }
    codebuild.put_resource_policy(resourceArn=project_arn, policy=json.dumps(policy_v2))
    raw_v2 = codebuild.get_resource_policy(resourceArn=project_arn)["policy"]
    fetched_v2 = json.loads(raw_v2)

    # Last write must fully REPLACE, not merge with, the first write.
    assert len(fetched_v2["Statement"]) == 1, (
        f"old and new statements were merged instead of replaced: {fetched_v2}"
    )
    assert fetched_v2["Statement"][0]["Sid"] == "SecondWriterStatement", (
        f"expected Sid 'SecondWriterStatement', got {fetched_v2['Statement'][0].get('Sid')!r}"
    )
    action_v2 = fetched_v2["Statement"][0]["Action"]
    action_v2 = action_v2 if isinstance(action_v2, list) else [action_v2]
    assert set(action_v2) == {
        "codebuild:BatchGetProjects",
        "codebuild:BatchGetBuilds",
        "codebuild:ListBuildsForProject",
    }, f"expected the second writer's full action set, got {set(action_v2)}"
    assert "FirstWriterStatement" not in raw_v2, "first writer's statement leaked into the replaced policy"

    # The teardown already deletes this policy; make that a free negative assertion:
    # gone via an independent read, with the specific not-found code, and the underlying
    # project (which the policy does not own) is unaffected.
    _delete_policy_when_settled(codebuild, project_arn)
    try:
        codebuild.get_resource_policy(resourceArn=project_arn)
        raise AssertionError("GetResourcePolicy still returned a policy after DeleteResourcePolicy")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException after delete, got {code!r}"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == "Resource ARN resource policy does not exist", (
            f"unexpected message: {message!r}"
        )
    still_there = codebuild.batch_get_projects(names=[project_name])["projects"]
    assert len(still_there) == 1 and still_there[0]["arn"] == project_arn, (
        f"deleting the resource policy must not affect the project itself, got {still_there}"
    )


# ===== helpers =====
_QUICK_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-ok\n"


def _delete_policy_when_settled(codebuild, resource_arn, deadline_s=30.0, poll_s=2.0) -> None:
    """DeleteResourcePolicy right after PutResourcePolicy can race CodeBuild's async policy
    write (InvalidInputException / InflightPolicy); retry until the write settles, and raise
    on the deadline."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            codebuild.delete_resource_policy(resourceArn=resource_arn)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            inflight = err.get("Code") == "InvalidInputException" and "InflightPolicy" in err.get("Message", "")
            if inflight and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _try(fn) -> None:
    """Teardown call: an already-absent resource is fine; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _make_codebuild_role(ctx) -> str:
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        _try(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
        _try(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "s3:*",
                    "ssmmessages:*",
                    "ssm:StartSession",
                    "codebuild:*",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return role_arn


def _create_no_source_project(
    ctx, role_arn: str, buildspec: str, extra: dict[str, Any] | None = None
) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-proj-")
    kwargs: dict[str, Any] = dict(
        name=name,
        source={"type": "NO_SOURCE", "buildspec": buildspec},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    if extra:
        kwargs.update(extra)

    # New IAM roles are not immediately assumable by codebuild.amazonaws.com everywhere,
    # so CreateProject can reject with InvalidInputException for a few seconds after the
    # role is created; retry instead of assuming a fixed propagation delay.
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException":
                last_err = e
                time.sleep(5)
                continue
            raise
    else:
        assert last_err is not None, "CreateProject retry loop exited with no recorded error"
        raise last_err
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
