"""deploy-cfn-apigateway-restapi-invalid-apikeysourcetype-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-apigateway-restapi-invalid-apikeysourcetype-rejected"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]


def _template(api_name: str, api_key_source: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RestApi": {
                    "Type": "AWS::ApiGateway::RestApi",
                    "Properties": {"Name": api_name, "ApiKeySourceType": api_key_source},
                },
            },
            "Outputs": {
                "RestApiId": {"Value": {"Ref": "RestApi"}},
            },
        }
    )


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ATTEMPT_COUNT = re.compile(r"SDK Attempt Count: \d+")


def _masked(text: str) -> str:
    """``text`` with every request id and the SDK attempt count replaced by a fixed token."""
    return _ATTEMPT_COUNT.sub("SDK Attempt Count: <n>", _UUID.sub("<id>", text))


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks until a non-IN_PROGRESS StackStatus; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if not status.endswith("IN_PROGRESS"):
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


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
    raise AssertionError(
        f"stack {stack_name} not deleted within {timeout_s}s (last status {status})"
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation RestApi naming an ApiKeySourceType outside HEADER/AUTHORIZER fails the
    stack with the enum violation CloudFormation reports, leaving no RestApi behind, while the
    same template with AUTHORIZER reaches CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    bad_stack_name = ctx.unique_name("sim2real-cfn-badkeysrc-")
    bad_api_name = ctx.unique_name("sim2real-cfn-badkeysrc-api-")

    cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=_template(bad_api_name, "BOGUS"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, bad_stack_name))

    status = _wait_terminal(cfn, bad_stack_name)
    assert status == "ROLLBACK_COMPLETE", f"invalid ApiKeySourceType settled at {status!r}"

    events = cfn.describe_stack_events(StackName=bad_stack_name)["StackEvents"]
    failed = [
        e
        for e in events
        if e["LogicalResourceId"] == "RestApi" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(failed) == 1, f"expected exactly one RestApi CREATE_FAILED event, got {failed!r}"
    reason = failed[0]["ResourceStatusReason"]
    expected_reason = (
        "Resource handler returned message: \"1 validation error detected: Value 'BOGUS' at "
        "'createRestApiInput.apiKeySource' failed to satisfy constraint: Member must satisfy "
        "enum value set: [AUTHORIZER, HEADER] (Service: ApiGateway, Status Code: 400, "
        'Request ID: <id>) (SDK Attempt Count: <n>)" '
        "(RequestToken: <id>, HandlerErrorCode: GeneralServiceException)"
    )
    assert _masked(reason) == expected_reason, (
        f"unexpected CREATE_FAILED reason (ids masked) {_masked(reason)!r}, raw {reason!r}"
    )

    apis = [a for page in apigw.get_paginator("get_rest_apis").paginate() for a in page["items"]]
    assert not any(a["name"] == bad_api_name for a in apis), (
        f"a RestApi named {bad_api_name!r} exists after the rolled-back stack"
    )

    # Positive control: the identical template with a valid ApiKeySourceType reaches CREATE_COMPLETE.
    good_stack_name = ctx.unique_name("sim2real-cfn-goodkeysrc-")
    good_api_name = ctx.unique_name("sim2real-cfn-goodkeysrc-api-")
    cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=_template(good_api_name, "AUTHORIZER"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, good_stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=good_stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    good_status = cfn.describe_stacks(StackName=good_stack_name)["Stacks"][0]["StackStatus"]
    assert good_status == "CREATE_COMPLETE", f"the valid template settled at {good_status!r}"
    good_api_id = cfn.describe_stack_resource(
        StackName=good_stack_name, LogicalResourceId="RestApi"
    )["StackResourceDetail"]["PhysicalResourceId"]
    good_api = apigw.get_rest_api(restApiId=good_api_id)
    assert good_api["apiKeySource"] == "AUTHORIZER", (
        f"control RestApi apiKeySource was {good_api.get('apiKeySource')!r}, expected AUTHORIZER"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
