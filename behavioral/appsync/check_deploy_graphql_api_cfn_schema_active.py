"""deploy-graphql-api-cfn-schema-active."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-graphql-api-cfn-schema-active"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a GraphQLApi + GraphQLSchema stack is CREATE_COMPLETE, schema creation status is SUCCESS
    and the introspection schema contains the deployed Query field.
    """
    api_name = ctx.unique_name("sim2real-appsync-api-")
    template = {
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
                    "Definition": "type Query {\n  echo(msg: String): String\n}\n",
                },
            },
        },
        "Outputs": {"ApiId": {"Value": {"Fn::GetAtt": ["Api", "ApiId"]}}},
    }

    stack_name, outputs = _deploy_stack(ctx, template, capabilities=[])
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    api_id = outputs["ApiId"]

    appsync = ctx.client("appsync")

    api = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert api["name"] == api_name, f"expected api name {api_name!r}, got {api['name']!r}"
    assert api["authenticationType"] == "API_KEY", (
        f"expected authenticationType API_KEY, got {api['authenticationType']!r}"
    )

    status = appsync.get_schema_creation_status(apiId=api_id)["status"]
    assert status == "SUCCESS", f"expected schema SUCCESS after stack CREATE_COMPLETE, got {status}"

    schema_resp = appsync.get_introspection_schema(apiId=api_id, format="SDL")
    schema_text = schema_resp["schema"].read().decode("utf-8")
    assert "echo(msg: String): String" in schema_text, (
        f"expected the deployed echo(msg: String): String field signature in the introspected "
        f"schema, got: {schema_text!r}"
    )
    assert "type Query" in schema_text, f"expected a Query root type in introspected schema, got: {schema_text!r}"




def _deploy_stack(ctx: Any, template: dict, capabilities=None, params=None):
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-appsync-cfn-")
    kwargs = {
        "StackName": name,
        "TemplateBody": json.dumps(template),
        "Capabilities": capabilities if capabilities is not None else ["CAPABILITY_IAM"],
    }
    if params:
        kwargs["Parameters"] = params
    cfn.create_stack(**kwargs)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    outputs_raw = cfn.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    outputs = {o["OutputKey"]: o["OutputValue"] for o in outputs_raw}
    return name, outputs


def _delete_stack(ctx: Any, name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
