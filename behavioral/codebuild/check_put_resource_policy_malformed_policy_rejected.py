"""put-resource-policy-malformed-policy-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-policy-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a syntactically invalid policy document is rejected with
    InvalidInputException and attaches nothing (GetResourcePolicy reports ResourceNotFoundException),
    while a well-formed document is accepted and retrievable (positive control)."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-pol-")
    project = _create_project(ctx, project_name, role_arn)
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))
    project_arn = project["arn"]

    def _put_malformed() -> None:
        codebuild.put_resource_policy(resourceArn=project_arn, policy="{this is not json")

    code, code_msg = _client_error(_put_malformed)
    assert code == "InvalidInputException", f"unexpected code: {code}"
    assert code_msg == "Problem parsing given policy", f"unexpected message: {code_msg!r}"

    # Effect absent: no resource policy was attached by the rejected call.
    def _get_policy() -> None:
        codebuild.get_resource_policy(resourceArn=project_arn)

    code_get, code_get_msg = _client_error(_get_policy)
    assert code_get == "ResourceNotFoundException", f"unexpected code: {code_get}"
    assert code_get_msg == "Resource ARN resource policy does not exist", f"unexpected message: {code_get_msg!r}"

    # Positive control: a well-formed policy document is accepted and persists.
    # Use the caller's own account as principal so account-existence validation
    # (independent of the malformed-JSON boundary under test) doesn't interfere.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": [account_id]},
            "Action": [
                "codebuild:BatchGetProjects",
                "codebuild:BatchGetBuilds",
                "codebuild:ListBuildsForProject",
            ],
            "Resource": project_arn,
        }],
    }
    try:
        put_resp = codebuild.put_resource_policy(resourceArn=project_arn, policy=json.dumps(valid_policy))
    except ClientError as err:
        code = err.response["Error"]["Code"]
        raise AssertionError(f"well-formed policy unexpectedly rejected: {code}") from err
    ctx.on_cleanup(lambda: _best_effort_delete_policy(codebuild, project_arn))
    assert put_resp["resourceArn"] == project_arn, (
        f"unexpected resourceArn in put response: {put_resp.get('resourceArn')}"
    )
    fetched = json.loads(codebuild.get_resource_policy(resourceArn=project_arn)["policy"])
    assert fetched["Statement"][0]["Resource"] == project_arn, (
        f"stored resource {fetched['Statement'][0]['Resource']} != {project_arn}"
    )
    assert set(fetched["Statement"][0]["Action"]) == set(valid_policy["Statement"][0]["Action"]), (
        f"stored actions {fetched['Statement'][0]['Action']} != {valid_policy['Statement'][0]['Action']}"
    )


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses fails here."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "put-resource-policy-malformed-policy-rejected"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_project(ctx, name: str, role_arn: str, **overrides: Any) -> dict:
    codebuild = ctx.client("codebuild")
    params: dict[str, Any] = {
        "name": name,
        "source": {
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo default\n",
        },
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role_arn,
        "logsConfig": {
            "cloudWatchLogs": {"status": "DISABLED"},
            "s3Logs": {"status": "DISABLED"},
        },
        "tags": [{"key": "sim2real", "value": "put-resource-policy-malformed-policy-rejected"}],
    }
    params.update(overrides)
    last_err = None
    for _ in range(10):
        try:
            return codebuild.create_project(**params)["project"]
        except codebuild.exceptions.InvalidInputException as err:
            last_err = err
            time.sleep(3)
    raise last_err


def _best_effort_delete_policy(codebuild, resource_arn: str) -> None:
    """Teardown: returns when the policy is already gone; any other failure raises."""
    try:
        codebuild.delete_resource_policy(resourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
