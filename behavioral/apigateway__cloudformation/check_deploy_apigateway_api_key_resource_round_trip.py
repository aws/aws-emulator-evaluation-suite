"""deploy-apigateway-api-key-resource-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-api-key-resource-round-trip"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ApiGateway::ApiKey is readable through GetApiKey with
    the Name, Description and Enabled the template set, its Fn::GetAtt APIKeyId matches the
    Ref, and GetApiKey fails NotFoundException once the stack that created it is deleted."""
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    stack_name = ctx.unique_name("sim2real-cfn-apikey-")
    key_name = ctx.unique_name("sim2real-apikey-")
    description = ctx.unique_name("sim2real-apikey-desc-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SimKey": {
                "Type": "AWS::ApiGateway::ApiKey",
                "Properties": {
                    "Name": key_name,
                    "Description": description,
                    "Enabled": True,
                },
            }
        },
        "Outputs": {
            "ApiKeyRef": {"Value": {"Ref": "SimKey"}},
            "ApiKeyIdAttr": {"Value": {"Fn::GetAtt": ["SimKey", "APIKeyId"]}},
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    assert outputs["ApiKeyRef"] == outputs["ApiKeyIdAttr"], (
        f"Ref(SimKey)={outputs['ApiKeyRef']!r} and Fn::GetAtt SimKey.APIKeyId="
        f"{outputs['ApiKeyIdAttr']!r} disagree on the key id"
    )
    key_id = outputs["ApiKeyRef"]

    key = apigw.get_api_key(apiKey=key_id)
    assert key["name"] == key_name, f"expected name {key_name!r}, GetApiKey returned {key['name']!r}"
    assert key["description"] == description, (
        f"expected description {description!r}, GetApiKey returned {key['description']!r}"
    )
    assert key["enabled"] is True, f"expected enabled True, GetApiKey returned {key['enabled']!r}"

    # Graded in-band teardown: delete the stack and confirm the key is genuinely gone,
    # not merely reported deleted by CloudFormation.
    _delete_stack(ctx, stack_name)
    code, message = _error(lambda: apigw.get_api_key(apiKey=key_id))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}: {message!r}"
    assert message == "Invalid API Key identifier specified", f"unexpected message {message!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_stack(ctx, stack_name: str, timeout_s: float = 300.0) -> None:
    """Delete the stack and wait for it to vanish; DELETE_FAILED or the deadline raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if not stacks:
            return
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
