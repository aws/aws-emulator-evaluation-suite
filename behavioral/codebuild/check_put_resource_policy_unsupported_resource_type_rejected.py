"""put-resource-policy-unsupported-resource-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-unsupported-resource-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy and GetResourcePolicy on a non-Project/ReportGroup ARN both raise
    InvalidInputException (rejected before lookup); the same policy on a real Project ARN
    succeeds and round-trips through GetResourcePolicy."""
    codebuild = ctx.client("codebuild")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_codebuild_role(ctx)
    project = _create_minimal_project(ctx, role_arn)
    project_arn = codebuild.batch_get_projects(names=[project])["projects"][0]["arn"]

    bogus_arn = f"arn:aws:s3:::{ctx.unique_name('sim2real-cb-notreal-')}"
    policy_template = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": [f"arn:aws:iam::{account_id}:root"]},
                "Action": ["codebuild:BatchGetProjects"],
            }
        ],
    }

    bogus_policy = json.loads(json.dumps(policy_template))
    bogus_policy["Statement"][0]["Resource"] = bogus_arn
    code, code_msg = _client_error(
        lambda: codebuild.put_resource_policy(policy=json.dumps(bogus_policy), resourceArn=bogus_arn)
    )
    assert code == "InvalidInputException"
    assert code_msg == "Resource ARN is invalid", f"unexpected message: {code_msg!r}"

    not_found_code, not_found_code_msg = _client_error(lambda: codebuild.get_resource_policy(resourceArn=bogus_arn))
    assert not_found_code == "InvalidInputException", not_found_code
    assert not_found_code_msg == "Resource ARN is invalid", f"unexpected message: {not_found_code_msg!r}"

    # positive control: the same policy shape against a real project ARN is
    # accepted and persists.
    control_policy = json.loads(json.dumps(policy_template))
    control_policy["Statement"][0]["Resource"] = project_arn
    put_resp = codebuild.put_resource_policy(policy=json.dumps(control_policy), resourceArn=project_arn)
    ctx.on_cleanup(lambda: codebuild.delete_resource_policy(resourceArn=project_arn))
    assert put_resp["resourceArn"] == project_arn
    read_back = json.loads(codebuild.get_resource_policy(resourceArn=project_arn)["policy"])
    assert read_back["Statement"][0]["Resource"] == project_arn
    action = read_back["Statement"][0]["Action"]
    actions = action if isinstance(action, list) else [action]
    assert actions == control_policy["Statement"][0]["Action"]


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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
                tags=[{"key": "sim2real", "value": "true"}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise
    ctx.on_cleanup(lambda: codebuild.delete_project(name=name))
    return name


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
