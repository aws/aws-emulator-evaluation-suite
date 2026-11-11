"""resource-policy-malformed-json-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-malformed-json-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with syntactically invalid JSON is rejected and never stored."""
    codebuild = ctx.client("codebuild")
    sts = ctx.client("sts")

    role_arn = _create_service_role(ctx)
    account_id = sts.get_caller_identity()["Account"]

    project_name = ctx.unique_name("sim2real-cb-proj-")
    _create_project_with_retry(codebuild, _basic_project_params(role_arn, project_name))
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))
    project_arn = codebuild.batch_get_projects(names=[project_name])["projects"][0]["arn"]

    malformed = '{ "Version": "2012-10-17", "Statement": [ this is not json '
    code, code_msg = _client_error(
        lambda: codebuild.put_resource_policy(policy=malformed, resourceArn=project_arn)
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    assert code_msg == "Problem parsing given policy", f"unexpected message: {code_msg!r}"

    # effect absent: the malformed policy was never stored
    code2, code2_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=project_arn))
    assert code2 == "ResourceNotFoundException", f"expected no stored policy, got {code2}"
    assert code2_msg == "Resource ARN resource policy does not exist", f"unexpected message: {code2_msg!r}"

    # positive control: a syntactically valid resource policy is accepted and persists
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountRootDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["codebuild:BatchGetProjects", "codebuild:ListBuildsForProject"],
                "Resource": project_arn,
            }
        ],
    }
    put_resp = codebuild.put_resource_policy(
        policy=json.dumps(valid_policy), resourceArn=project_arn
    )
    assert put_resp["resourceArn"] == project_arn, (
        f"expected PutResourcePolicy to echo {project_arn}, got {put_resp['resourceArn']}"
    )
    ctx.on_cleanup(lambda: codebuild.delete_resource_policy(resourceArn=project_arn))

    stored = json.loads(codebuild.get_resource_policy(resourceArn=project_arn)["policy"])
    assert stored["Statement"][0]["Resource"] == project_arn, (
        f"expected the persisted policy's Resource to be {project_arn}, got "
        f"{stored['Statement'][0]['Resource']}"
    )
    assert set(stored["Statement"][0]["Action"]) == set(valid_policy["Statement"][0]["Action"]), (
        f"expected persisted Action {valid_policy['Statement'][0]['Action']}, got "
        f"{stored['Statement'][0]['Action']}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_project_with_retry(codebuild, params: dict[str, Any], timeout_s: float = 90.0) -> None:
    """CreateProject, retrying through IAM trust-policy propagation lag: the freshly-created
    service role may not yet be assumable by CodeBuild."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(**params)
            return
        except codebuild.exceptions.InvalidInputException as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreateProject never succeeded (IAM role propagation?): {last_err}")


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


def _basic_project_params(role_arn: str, name: str) -> dict[str, Any]:
    return {
        "name": name,
        "source": {
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n",
        },
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role_arn,
        "tags": [{"key": "sim2real", "value": CHECK}],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
