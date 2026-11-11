"""deploy-data-source-resolver-cfn-executes-query."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-data-source-resolver-cfn-executes-query"
GROUP = "server-side"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AMAZON_DYNAMODB DataSource + Resolvers work end to end: a GraphQL mutation
    writes the row (confirmed by DynamoDB GetItem) and a query reads it back.
    """
    api_name = ctx.unique_name("sim2real-appsync-api-")
    schema_def = (
        "type Item {\n"
        "  id: String\n"
        "  val: String\n"
        "}\n"
        "type Query {\n"
        "  getItem(id: String!): Item\n"
        "}\n"
        "type Mutation {\n"
        "  putItem(id: String!, val: String!): Item\n"
        "}\n"
    )
    put_request = (
        '{\n'
        '  "version": "2018-05-29",\n'
        '  "operation": "PutItem",\n'
        '  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) },\n'
        '  "attributeValues": { "val": $util.dynamodb.toDynamoDBJson($ctx.args.val) }\n'
        '}'
    )
    get_request = (
        '{\n'
        '  "version": "2018-05-29",\n'
        '  "operation": "GetItem",\n'
        '  "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) }\n'
        '}'
    )
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                    "BillingMode": "PAY_PER_REQUEST",
                },
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "appsync.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "DDBAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
                                        "Resource": {"Fn::GetAtt": ["Table", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "Api": {
                "Type": "AWS::AppSync::GraphQLApi",
                "Properties": {"Name": api_name, "AuthenticationType": "API_KEY"},
            },
            "Schema": {
                "Type": "AWS::AppSync::GraphQLSchema",
                "Properties": {"ApiId": {"Fn::GetAtt": ["Api", "ApiId"]}, "Definition": schema_def},
            },
            "DDBSource": {
                "Type": "AWS::AppSync::DataSource",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "Name": "DDBSource",
                    "Type": "AMAZON_DYNAMODB",
                    "DynamoDBConfig": {"AwsRegion": ctx.region, "TableName": {"Ref": "Table"}},
                    "ServiceRoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                },
            },
            "PutResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["Schema"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "TypeName": "Mutation",
                    "FieldName": "putItem",
                    "DataSourceName": {"Fn::GetAtt": ["DDBSource", "Name"]},
                    "RequestMappingTemplate": put_request,
                    "ResponseMappingTemplate": "$util.toJson($ctx.result)",
                },
            },
            "GetResolver": {
                "Type": "AWS::AppSync::Resolver",
                "DependsOn": ["Schema"],
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["Api", "ApiId"]},
                    "TypeName": "Query",
                    "FieldName": "getItem",
                    "DataSourceName": {"Fn::GetAtt": ["DDBSource", "Name"]},
                    "RequestMappingTemplate": get_request,
                    "ResponseMappingTemplate": "$util.toJson($ctx.result)",
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Fn::GetAtt": ["Api", "ApiId"]}},
            "TableName": {"Value": {"Ref": "Table"}},
        },
    }

    stack_name, outputs = _deploy_stack(ctx, template, capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    api_id = outputs["ApiId"]
    table_name = outputs["TableName"]

    appsync = ctx.client("appsync")
    resolver = appsync.get_resolver(apiId=api_id, typeName="Mutation", fieldName="putItem")["resolver"]
    assert resolver["dataSourceName"] == "DDBSource"

    api_key = appsync.create_api_key(apiId=api_id, description="sim2real test key")["apiKey"]["id"]
    endpoint = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]["uris"]["GRAPHQL"]

    item_id = ctx.unique_name("item-")
    status, payload = _graphql_query(
        ctx, endpoint,
        api_key,
        "mutation Put($id: String!, $val: String!) { putItem(id: $id, val: $val) { id val } }",
        {"id": item_id, "val": "hello-world"},
    )
    assert status == 200 and "errors" not in payload, f"putItem failed: {payload}"
    assert payload["data"]["putItem"] == {"id": item_id, "val": "hello-world"}

    status, payload = _graphql_query(
        ctx, endpoint,
        api_key,
        "query Get($id: String!) { getItem(id: $id) { id val } }",
        {"id": item_id},
    )
    assert status == 200 and "errors" not in payload, f"getItem failed: {payload}"
    assert payload["data"]["getItem"] == {"id": item_id, "val": "hello-world"}

    dynamodb = ctx.client("dynamodb")
    row = dynamodb.get_item(
        TableName=table_name, Key={"id": {"S": item_id}}, ConsistentRead=True
    ).get("Item")
    assert row is not None, "putItem resolver did not persist a row in DynamoDB"
    assert row["val"]["S"] == "hello-world"




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


def _http_post_json(ctx, url: str, headers: dict, body_obj: dict, timeout: float = 20.0):
    data = json.dumps(body_obj).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=data, headers={**headers, **route_headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _graphql_query(ctx, endpoint: str, api_key: str, query: str, variables: dict | None = None):
    headers = {"Content-Type": "application/json", "x-api-key": api_key}
    body: dict[str, Any] = {"query": query}
    if variables:
        body["variables"] = variables
    return _http_post_json(ctx, endpoint, headers, body)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
