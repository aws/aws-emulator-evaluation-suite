"""cfn-deploy-iot-thing-custom-resource-lambda-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iot-thing-custom-resource-lambda-positive"
GROUP = "deployment-order"
SERVICES = ["iot", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation custom resource backed by Lambda creates an IoT thing during stack
    deployment, and the thing exists (describable) after CREATE_COMPLETE; deleting the stack
    drives the custom resource's Delete branch, which removes the thing."""
    thing_name = _xname(ctx, "thing").replace("-", "_")
    template = json.dumps(_stack_template(thing_name))

    result = _deploy_cfn(ctx, template)
    iot = ctx.client("iot")
    ctx.on_cleanup(lambda: _delete_thing_ignore(ctx, thing_name))

    described = iot.describe_thing(thingName=thing_name)
    assert described["thingName"] == thing_name, (
        f"expected describe_thing to report thingName={thing_name!r}, got {described.get('thingName')!r}"
    )
    assert result["outputs"]["ThingName"] == thing_name, (
        f"expected stack output ThingName={thing_name!r}, got {result['outputs'].get('ThingName')!r}"
    )

    _delete_stack_and_wait(ctx, result["stack_name"])
    code, message = _error(lambda: iot.describe_thing(thingName=thing_name))
    assert code == "ResourceNotFoundException", (
        f"expected the custom resource's Delete branch to remove {thing_name!r} on stack "
        f"deletion, got describe_thing error {code!r}"
    )
    expected = f"Thing {ctx.account}:{thing_name} not found."
    assert message == expected, f"expected describe_thing message {expected!r}, got {message!r}"


def _error(fn):
    """The (code, message) a call is refused with; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_thing_ignore(ctx, thing_name: str) -> None:
    """Teardown: a thing the stack already removed is clean; anything else raises."""
    try:
        ctx.client("iot").delete_thing(thingName=thing_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _stack_template(thing_name: str) -> dict[str, Any]:
    handler_code = (
        "import json\n"
        "import urllib.request\n"
        "import boto3\n\n"
        "def send(event, context, status, physical_id, reason=None):\n"
        "    body = json.dumps({\n"
        "        'Status': status,\n"
        "        'Reason': reason or 'see logs',\n"
        "        'PhysicalResourceId': physical_id,\n"
        "        'StackId': event['StackId'],\n"
        "        'RequestId': event['RequestId'],\n"
        "        'LogicalResourceId': event['LogicalResourceId'],\n"
        "        'Data': {'ThingName': physical_id},\n"
        "    }).encode('utf-8')\n"
        "    req = urllib.request.Request(\n"
        "        event['ResponseURL'], data=body, method='PUT',\n"
        "        headers={'content-type': '', 'content-length': str(len(body))},\n"
        "    )\n"
        "    urllib.request.urlopen(req)\n\n"
        "def handler(event, context):\n"
        "    iot = boto3.client('iot')\n"
        "    req_type = event['RequestType']\n"
        "    props = event.get('ResourceProperties', {})\n"
        "    try:\n"
        "        if req_type == 'Create':\n"
        "            physical_id = props['ThingName']\n"
        "            iot.create_thing(thingName=physical_id)\n"
        "        elif req_type == 'Update':\n"
        "            physical_id = event['PhysicalResourceId']\n"
        "        else:\n"
        "            physical_id = event['PhysicalResourceId']\n"
        "            try:\n"
        "                iot.delete_thing(thingName=physical_id)\n"
        "            except Exception:\n"
        "                pass\n"
        "        send(event, context, 'SUCCESS', physical_id)\n"
        "    except Exception as exc:\n"
        "        send(event, context, 'FAILED', event.get('PhysicalResourceId', 'failed'), reason=str(exc))\n"
    )
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "CrRole": {
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
                    "Policies": [
                        {
                            "PolicyName": "inline",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["iot:CreateThing", "iot:DeleteThing", "iot:DescribeThing"],
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "CrFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["CrRole", "Arn"]},
                    "Timeout": 60,
                    "Code": {"ZipFile": handler_code},
                },
            },
            "ThingResource": {
                "Type": "Custom::Thing",
                "Properties": {
                    "ServiceToken": {"Fn::GetAtt": ["CrFunction", "Arn"]},
                    "ThingName": thing_name,
                },
            },
        },
        "Outputs": {"ThingName": {"Value": {"Ref": "ThingResource"}}},
    }


_XSVC_PREFIX = "sim2real-xsvc-"


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
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
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
