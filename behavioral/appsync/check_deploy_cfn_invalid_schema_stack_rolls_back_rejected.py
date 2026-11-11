"""deploy-cfn-invalid-schema-stack-rolls-back-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-invalid-schema-stack-rolls-back-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An invalid AWS::AppSync::GraphQLSchema definition rolls the stack back with no orphaned API;
    the same template with a valid schema deploys, and its API is gone after stack delete.
    """
    cfn = ctx.client("cloudformation")
    appsync = ctx.client("appsync")

    bad_name = ctx.unique_name("sim2real-appsync-bad-")
    bad_template = _api_and_schema_template(bad_name, "this is not a valid graphql schema at all !!!")
    bad_stack = ctx.unique_name("sim2real-appsync-cfn-bad-")
    cfn.create_stack(
        StackName=bad_stack, TemplateBody=json.dumps(bad_template), Capabilities=[]
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, bad_stack))

    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=bad_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
        raise AssertionError("expected the invalid-schema stack creation to fail, but it succeeded")
    except Exception as exc:
        if isinstance(exc, AssertionError):
            raise
        # WaiterError: the stack failed to reach CREATE_COMPLETE, as expected.

    final_status = cfn.describe_stacks(StackName=bad_stack)["Stacks"][0]["StackStatus"]
    assert final_status == "ROLLBACK_COMPLETE", f"unexpected final stack status: {final_status}"

    # An Api created before the Schema failure must have been rolled back with the stack.
    resources = cfn.describe_stack_resources(StackName=bad_stack)["StackResources"]
    api_resources = [r for r in resources if r["LogicalResourceId"] == "Api"]
    if api_resources and api_resources[0].get("PhysicalResourceId"):
        orphan_api_id = api_resources[0]["PhysicalResourceId"]
        err = _error(lambda: appsync.get_graphql_api(apiId=orphan_api_id))
        assert err == ("NotFoundException", "API not found."), (
            f"expected the rolled-back Api {orphan_api_id} to be gone, got {err}"
        )

    good_name = ctx.unique_name("sim2real-appsync-good-")
    good_template = _api_and_schema_template(good_name, "type Query {\n  echo(msg: String): String\n}\n")
    good_stack = ctx.unique_name("sim2real-appsync-cfn-good-")
    cfn.create_stack(
        StackName=good_stack, TemplateBody=json.dumps(good_template), Capabilities=[]
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, good_stack))
    waiter.wait(StackName=good_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=good_stack)["Stacks"][0].get("Outputs", [])
    }
    good_api_id = outputs["ApiId"]
    good_api = appsync.get_graphql_api(apiId=good_api_id)["graphqlApi"]
    assert good_api["name"] == good_name, f"expected api name {good_name!r}, got {good_api['name']!r}"
    schema_status = appsync.get_schema_creation_status(apiId=good_api_id)["status"]
    assert schema_status == "SUCCESS", f"expected schema SUCCESS, got {schema_status}"

    cfn.delete_stack(StackName=good_stack)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=good_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )
    err = _error(lambda: appsync.get_graphql_api(apiId=good_api_id))
    assert err == ("NotFoundException", "API not found."), (
        f"expected the torn-down Api {good_api_id} to be gone, got {err}"
    )




def _api_and_schema_template(api_name: str, definition: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Api": {
                "Type": "AWS::AppSync::GraphQLApi",
                "Properties": {"Name": api_name, "AuthenticationType": "API_KEY"},
            },
            "Schema": {
                "Type": "AWS::AppSync::GraphQLSchema",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "Definition": definition,
                },
            },
        },
        "Outputs": {"ApiId": {"Value": {"Fn::GetAtt": ["Api", "ApiId"]}}},
    }


def _delete_stack(ctx: Any, name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
