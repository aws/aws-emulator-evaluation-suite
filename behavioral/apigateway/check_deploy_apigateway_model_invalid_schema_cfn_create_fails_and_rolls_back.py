"""deploy-apigateway-model-invalid-schema-cfn-create-fails-and-rolls-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-model-invalid-schema-cfn-create-fails-and-rolls-back"
GROUP = "server-side"
SERVICES = ["apigateway", "cloudformation"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack whose AWS::ApiGateway::Model has a malformed schema never
    completes: the create rolls the whole stack back, leaving no RestApi behind. A sibling
    stack whose Model carries a well-formed schema creates cleanly, as the positive control.
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    bad_stack = ctx.unique_name("sim2real-apigw-badmodel-")
    bad_model_name = f"{ctx.unique_name('SimParityBroken')}"
    malformed_schema = '{"title": "x", "type": "object", "properties": {'  # truncated: not valid JSON

    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(ctx.unique_name("sim2real-apigw-badmodel-api-"),
                               bad_model_name, malformed_schema),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    bad_status = _wait_settled(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a Model with a malformed schema settled the stack at {bad_status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )

    bad_api_id = _resource_physical_id(cfn, bad_stack, "Api")
    code, message = _error(lambda: apigw.get_rest_api(restApiId=bad_api_id))
    assert code == "NotFoundException", (
        f"the rolled-back stack's RestApi {bad_api_id!r} answered {code!r}, expected NotFoundException"
    )
    assert message == f"Invalid API identifier specified {ctx.account}:{bad_api_id}", (
        f"unexpected NotFound message for the rolled-back RestApi: {message!r}"
    )

    # ---- positive control: the same shape with a well-formed schema creates cleanly ----------
    good_stack = ctx.unique_name("sim2real-apigw-goodmodel-")
    good_model_name = f"{ctx.unique_name('SimParityWorking')}"
    good_schema = json.dumps({"title": "x", "type": "object", "properties": {"id": {"type": "string"}}})

    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(ctx.unique_name("sim2real-apigw-goodmodel-api-"),
                               good_model_name, good_schema),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    good_status = _wait_settled(cfn, good_stack)
    assert good_status == "CREATE_COMPLETE", (
        f"a Model with a well-formed schema settled the stack at {good_status!r}, "
        f"expected CREATE_COMPLETE"
    )

    good_api_id = _resource_physical_id(cfn, good_stack, "Api")
    created = apigw.get_model(restApiId=good_api_id, modelName=good_model_name)
    assert json.loads(created["schema"]) == json.loads(good_schema), (
        f"GetModel schema {created['schema']!r} does not match the deployed template's schema"
    )


def _template(api_name: str, model_name: str, schema) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": api_name}},
            "ItemModel": {
                "Type": "AWS::ApiGateway::Model",
                "Properties": {
                    "RestApiId": {"Ref": "Api"},
                    "ContentType": "application/json",
                    "Name": model_name,
                    "Schema": schema,
                },
            },
        },
    })


def _resource_physical_id(cfn, stack_name: str, logical_id: str) -> str:
    for resource in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]:
        if resource["LogicalResourceId"] == logical_id:
            physical_id = resource.get("PhysicalResourceId")
            assert physical_id, (
                f"{logical_id!r} in stack {stack_name!r} never obtained a physical id: {resource!r}"
            )
            return physical_id
    raise AssertionError(f"no resource {logical_id!r} recorded in stack {stack_name!r}")


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_settled(cfn, stack_name: str, timeout_s: float = 420.0, interval_s: float = 5.0) -> str:
    """Poll until the stack leaves every ``*_IN_PROGRESS`` state; return the settled status."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not settle within {timeout_s}s (last={status!r})")


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 420.0
    status = "never read"
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(f"stack {stack_name} did not delete within 420s (last={status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
