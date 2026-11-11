"""cli-workflow-cfn-outputs-drive-apigateway-stage-update."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile

from behavioral_harness import tags

CHECK = "cli-workflow-cfn-outputs-drive-apigateway-stage-update"
GROUP = "cli-workflow"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack Output (a Lambda ARN) read with the CLI and written to an API Gateway stage variable with the
    CLI persists: GetStage returns that value."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    stack_name = ctx.unique_name("sim2real-cfa-stack-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Runtime": "python3.12",
                    "Timeout": 10,
                    "Code": {"ZipFile": "def handler(event, context):\n    return {'ok': True}\n"},
                },
            },
        },
        "Outputs": {"LambdaArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}}},
    }

    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(template, f)
    ctx.on_cleanup(lambda: os.remove(tmp_path))

    _run_cli(
        ctx,
        [
            "cloudformation", "create-stack",
            "--stack-name", stack_name,
            "--template-body", f"file://{tmp_path}",
            "--capabilities", "CAPABILITY_IAM",
            "--tags", "Key=sim2real:managed,Value=true", "Key=sim2real:prefix,Value=sim2real-cfa",
        ],
    )
    ctx.on_cleanup(lambda: _run_cli(ctx, ["cloudformation", "delete-stack", "--stack-name", stack_name], check=False))
    _run_cli(ctx, ["cloudformation", "wait", "stack-create-complete", "--stack-name", stack_name])

    lambda_arn = _run_cli(
        ctx,
        [
            "cloudformation", "describe-stacks",
            "--stack-name", stack_name,
            "--query", "Stacks[0].Outputs[?OutputKey=='LambdaArn'].OutputValue",
            "--output", "text",
        ],
    ).strip()
    assert lambda_arn.startswith("arn:aws:lambda:"), f"unexpected LambdaArn output: {lambda_arn!r}"

    api_id, stage_name = _setup_deployed_mock_api(ctx)

    _run_cli(
        ctx,
        [
            "apigateway", "update-stage",
            "--rest-api-id", api_id,
            "--stage-name", stage_name,
            "--patch-operations", f"op=replace,path=/variables/lambdaArn,value={lambda_arn}",
        ],
    )

    apig = ctx.client("apigateway")
    stage = apig.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage.get("variables", {}).get("lambdaArn") == lambda_arn, (
        f"stage variable not persisted: {stage.get('variables')}"
    )


def _run_cli(ctx, args: list[str], check: bool = True) -> str:
    cmd = ["aws"] + args + ["--region", ctx.region]
    proc = subprocess.run(cmd, env=ctx.subprocess_env(), capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise AssertionError(f"CLI command failed: {' '.join(cmd)}\nstderr: {proc.stderr}")
    return proc.stdout


def _setup_deployed_mock_api(ctx) -> tuple[str, str]:
    apig = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-cfa-api-")
    api_id = apig.create_rest_api(
        name=api_name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cfa"}
    )["id"]
    ctx.on_cleanup(lambda: apig.delete_rest_api(restApiId=api_id))

    resources = apig.get_resources(restApiId=api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    apig.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apig.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apig.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apig.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "ok"}'},
    )

    stage_name = "prod"
    apig.create_deployment(restApiId=api_id, stageName=stage_name)
    return api_id, stage_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
