"""cfn-method-request-model-reference-rejected."""
from __future__ import annotations

import json
import re

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "cfn-method-request-model-reference-rejected"
GROUP = "resource-existence"
SERVICES = ["apigateway", "cloudformation"]

_PATH_PART = "widgets"
_HANDLER = re.compile(r'Resource handler returned message: "(.*?) \(Service: ApiGateway, '
                      r'Status Code: (\d+), Request ID: [0-9a-f-]+\) \(SDK Attempt Count: \d+\)" '
                      r'\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (\w+)\)')


def _template(name: str, *, model_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": name, "EndpointConfiguration": {"Types": ["REGIONAL"]}},
            },
            "Resource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": _PATH_PART,
                },
            },
            "Method": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "Resource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "RequestModels": {"application/json": model_name},
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [{"StatusCode": "200"}],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
        },
    })


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(cfn, stack_name: str):
    def run_undo() -> None:
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
            )
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in msg:
                return
            raise

    return run_undo


def _events(cfn, stack_name: str) -> list:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        out.extend(page["StackEvents"])
    return list(reversed(out))


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Method naming a never-created request model is rejected (BadRequestException) directly and
    through CloudFormation, whose stack rolls back leaving no RestApi; the Empty-model control deploys
    and its RestApi is gone (NotFoundException) once its stack is deleted."""
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    bad_model = ctx.unique_name("sim2real-nosuchmodel-")

    control_stack = ctx.unique_name("sim2real-cfnagwmodelctl-")
    broken_stack = ctx.unique_name("sim2real-cfnagwmodelbrk-")
    control_api_name = ctx.unique_name("sim2real-cfnagwmodelctl-restapi-")
    broken_api_name = ctx.unique_name("sim2real-cfnagwmodelbrk-restapi-")

    # Both launched before either is awaited, so neither outcome is an artefact of ordering.
    cfn.create_stack(StackName=control_stack, TemplateBody=_template(control_api_name, model_name="Empty"),
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(cfn, control_stack))
    cfn.create_stack(StackName=broken_stack, TemplateBody=_template(broken_api_name, model_name=bad_model),
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(cfn, broken_stack))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=control_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    ctl_status = cfn.describe_stacks(StackName=control_stack)["Stacks"][0]["StackStatus"]
    assert ctl_status == "CREATE_COMPLETE", f"control stack settled at {ctl_status!r}"
    ctl_resources = cfn.describe_stack_resources(StackName=control_stack)["StackResources"]
    ctl_phys = {r["LogicalResourceId"]: r["PhysicalResourceId"] for r in ctl_resources}
    ctl_method = ag.get_method(
        restApiId=ctl_phys["RestApi"], resourceId=ctl_phys["Resource"], httpMethod="GET"
    )
    assert ctl_method.get("requestModels") == {"application/json": "Empty"}, (
        f"control GetMethod requestModels were {ctl_method.get('requestModels')!r}"
    )

    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=broken_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except WaiterError:
        pass  # the waiter's success state is CREATE_COMPLETE; the rollback is read below instead
    brk_status = cfn.describe_stacks(StackName=broken_stack)["Stacks"][0]["StackStatus"]
    assert brk_status == "ROLLBACK_COMPLETE", (
        f"a Method naming a nonexistent model settled the stack at {brk_status!r}, expected "
        f"ROLLBACK_COMPLETE"
    )

    events = _events(cfn, broken_stack)
    failed = [e for e in events
              if e["LogicalResourceId"] == "Method" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(failed) == 1, f"expected exactly one Method CREATE_FAILED event, got {failed!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    match = _HANDLER.search(reason)
    assert match is not None, f"CREATE_FAILED reason did not match the handler-message shape: {reason!r}"
    inner_message, http_status, handler_code = match.group(1), match.group(2), match.group(3)
    assert handler_code == "InvalidRequest", f"HandlerErrorCode was {handler_code!r}"
    assert http_status == "400", f"the wrapped API Gateway status code was {http_status!r}"
    assert inner_message == f"Invalid model identifier specified: {bad_model}", (
        f"unexpected resource handler message {inner_message!r}"
    )

    created_api = next((e["PhysicalResourceId"] for e in events
                        if e["LogicalResourceId"] == "RestApi"
                        and e["ResourceStatus"] == "CREATE_COMPLETE"), None)
    assert created_api, f"the broken stack never created its RestApi to roll back"
    code, message = _error(lambda: ag.get_rest_api(restApiId=created_api))
    want = f"Invalid API identifier specified {ctx.account}:{created_api}"
    assert (code, message) == ("NotFoundException", want), (
        f"GetRestApi on the rolled-back RestApi answered {(code, message)!r}, expected "
        f"('NotFoundException', {want!r})"
    )

    # The same refusal, with the exact message, called directly rather than through CloudFormation's
    # wrapped resource-handler text.
    code, message = _error(
        lambda: ag.put_method(
            restApiId=ctl_phys["RestApi"], resourceId=ctl_phys["Resource"], httpMethod="POST",
            authorizationType="NONE", requestModels={"application/json": bad_model},
        )
    )
    assert code == "BadRequestException", f"direct PutMethod returned {code!r}: {message!r}"
    assert message == f"Invalid model identifier specified: {bad_model}", (
        f"direct PutMethod message was {message!r}"
    )

    # Both stacks are deleted in-band; the control's RestApi goes with its stack.
    for stack in (broken_stack, control_stack):
        cfn.delete_stack(StackName=stack)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
        code, message = _error(lambda stack=stack: cfn.describe_stacks(StackName=stack))
        assert (code, message) == ("ValidationError", f"Stack with id {stack} does not exist"), (
            f"DescribeStacks of the deleted stack answered {(code, message)!r}"
        )
    control_api = ctl_phys["RestApi"]
    code, message = _error(lambda: ag.get_rest_api(restApiId=control_api))
    want = f"Invalid API identifier specified {ctx.account}:{control_api}"
    assert (code, message) == ("NotFoundException", want), (
        f"GetRestApi on the deleted control RestApi answered {(code, message)!r}, expected "
        f"('NotFoundException', {want!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
