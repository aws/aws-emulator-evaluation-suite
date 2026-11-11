"""deploy-cfn-secret-rotation-lambda-stack."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-secret-rotation-lambda-stack"
GROUP = "deployment-order"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed secret + rotation Lambda + RotationSchedule actually rotates: forcing
    rotation drives the 4-step Lambda rotation protocol end to end, moving AWSCURRENT to a
    new version whose value was written by the rotation function."""
    secretsmanager = ctx.client("secretsmanager")

    rotation_code = (
        "def handler(event, context):\n"
        "    import boto3\n"
        "    client = boto3.client('secretsmanager')\n"
        "    arn = event['SecretId']\n"
        "    token = event['ClientRequestToken']\n"
        "    step = event['Step']\n"
        "    metadata = client.describe_secret(SecretId=arn)\n"
        "    versions = metadata['VersionIdsToStages']\n"
        "    if token not in versions:\n"
        "        raise ValueError('token not staged')\n"
        "    if 'AWSCURRENT' in versions[token]:\n"
        "        return\n"
        "    if step == 'createSecret':\n"
        "        try:\n"
        "            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage='AWSPENDING')\n"
        "        except client.exceptions.ResourceNotFoundException:\n"
        "            new_value = 'rotated-' + token[:8]\n"
        "            client.put_secret_value(\n"
        "                SecretId=arn, ClientRequestToken=token,\n"
        "                SecretString=new_value, VersionStages=['AWSPENDING'],\n"
        "            )\n"
        "    elif step == 'setSecret':\n"
        "        pass\n"
        "    elif step == 'testSecret':\n"
        "        pass\n"
        "    elif step == 'finishSecret':\n"
        "        current_version = None\n"
        "        for version, stages in metadata['VersionIdsToStages'].items():\n"
        "            if 'AWSCURRENT' in stages:\n"
        "                if version == token:\n"
        "                    return\n"
        "                current_version = version\n"
        "                break\n"
        "        client.update_secret_version_stage(\n"
        "            SecretId=arn, VersionStage='AWSCURRENT',\n"
        "            MoveToVersionId=token, RemoveFromVersionId=current_version,\n"
        "        )\n"
    )
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Secret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {"SecretString": "initial-value"},
            },
            "RotationExecRole": {
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
                    "Policies": [
                        {
                            "PolicyName": "rotation",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "secretsmanager:GetSecretValue",
                                            "secretsmanager:PutSecretValue",
                                            "secretsmanager:UpdateSecretVersionStage",
                                            "secretsmanager:DescribeSecret",
                                        ],
                                        "Resource": {"Ref": "Secret"},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "RotationLambda": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["RotationExecRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": rotation_code},
                },
            },
            "RotationPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "RotationLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "secretsmanager.amazonaws.com",
                },
            },
            "RotationSchedule": {
                "Type": "AWS::SecretsManager::RotationSchedule",
                "DependsOn": "RotationPermission",
                "Properties": {
                    "SecretId": {"Ref": "Secret"},
                    "RotationLambdaARN": {"Fn::GetAtt": ["RotationLambda", "Arn"]},
                    "RotationRules": {"AutomaticallyAfterDays": 30},
                },
            },
        },
        "Outputs": {
            "SecretArn": {"Value": {"Ref": "Secret"}},
        },
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    secret_arn = result["outputs"]["SecretArn"]

    before = secretsmanager.describe_secret(SecretId=secret_arn)
    old_current = next(
        v for v, stages in before["VersionIdsToStages"].items() if "AWSCURRENT" in stages
    )

    def _trigger_rotation():
        try:
            secretsmanager.rotate_secret(SecretId=secret_arn)
            return True
        except ClientError:
            return False

    _poll_until(
        _trigger_rotation,
        lambda ok: ok is True,
        timeout_s=60.0,
        interval_s=5.0,
        description="rotate_secret call accepted (rotation lambda permission propagated)",
    )

    def _current_version():
        desc = secretsmanager.describe_secret(SecretId=secret_arn)
        return next(v for v, stages in desc["VersionIdsToStages"].items() if "AWSCURRENT" in stages)

    _poll_until(
        _current_version,
        lambda v: v != old_current,
        timeout_s=180.0,
        interval_s=5.0,
        description="rotation moves AWSCURRENT to a new version",
    )

    final = secretsmanager.describe_secret(SecretId=secret_arn)
    assert "AWSPREVIOUS" in final["VersionIdsToStages"].get(old_current, []), (
        f"prior AWSCURRENT version {old_current} was not demoted to AWSPREVIOUS after "
        f"rotation; stages={final['VersionIdsToStages']}"
    )

    new_value = secretsmanager.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert new_value.startswith("rotated-"), (
        f"expected the rotation lambda's value (prefix 'rotated-') at AWSCURRENT, got {new_value!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
