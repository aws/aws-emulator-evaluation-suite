"""resource-policy-json-unicode-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-json-unicode-round-trip"
GROUP = "representation"
SERVICES = ["codebuild"]
_SCENARIO = CHECK


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy with a unicode Sid reads back from GetResourcePolicy as equal parsed JSON, and
    after DeleteResourcePolicy the read fails with ResourceNotFoundException."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project = _create_minimal_project(ctx, role_arn)
    project_arn = codebuild.batch_get_projects(names=[project])["projects"][0]["arn"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    unicode_sid = "研发团队-Ünïcödé-Développement-允许访问"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": unicode_sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "codebuild:BatchGetProjects",
                    "codebuild:BatchGetBuilds",
                    "codebuild:ListBuildsForProject",
                ],
                "Resource": project_arn,
            }
        ],
    }

    put_resp = codebuild.put_resource_policy(policy=json.dumps(policy_doc), resourceArn=project_arn)
    assert put_resp["resourceArn"] == project_arn, (
        f"put_resource_policy returned resourceArn {put_resp['resourceArn']!r}, expected {project_arn!r}"
    )

    read_back_raw = codebuild.get_resource_policy(resourceArn=project_arn)["policy"]
    read_back = json.loads(read_back_raw)
    assert read_back == policy_doc, f"policy round-trip mismatch: {read_back!r} != {policy_doc!r}"

    assert read_back["Statement"][0]["Sid"] == unicode_sid, (
        f"unicode Sid drifted: {read_back['Statement'][0]['Sid']!r} != {unicode_sid!r}"
    )

    codebuild.delete_resource_policy(resourceArn=project_arn)
    code, code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=project_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert code_msg == "Resource ARN resource policy does not exist", f"unexpected message: {code_msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


_ROLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ROLE_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline_policy = {
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
        RoleName=role_name, PolicyName="sim2real-cb-inline", PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-inline"))
    return role_arn


def _create_minimal_project(ctx, role_arn: str) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-proj-")
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n"
    deadline = time.monotonic() + 90.0
    while True:
        try:
            codebuild.create_project(
                name=name,
                source={"type": "NO_SOURCE", "buildspec": buildspec},
                artifacts={"type": "NO_ARTIFACTS"},
                environment={
                    "type": "LINUX_CONTAINER",
                    "image": "aws/codebuild/standard:7.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                },
                serviceRole=role_arn,
                tags=[{"key": "sim2real", "value": _SCENARIO}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise
    ctx.on_cleanup(lambda: codebuild.delete_project(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
