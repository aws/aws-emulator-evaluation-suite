"""deploy-resolver-cfn-insufficient-iam-permission-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-resolver-cfn-insufficient-iam-permission-rejected"
GROUP = "server-side"
SERVICES = ["appsync"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed DynamoDB resolver whose role grants only GetItem fails a PutItem
    mutation without writing the item while the GetItem resolver works; granting PutItem on the
    role then makes the identical mutation succeed, so the denial is that missing permission."""
    api_name = ctx.unique_name("sim2real-appsync-api-")
    schema_def = (
        "type Item {\n  id: String\n  val: String\n}\n"
        "type Query {\n  getItem(id: String!): Item\n}\n"
        "type Mutation {\n  putItem(id: String!, val: String!): Item\n}\n"
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
                            "PolicyName": "DDBReadOnly",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        # Deliberately missing dynamodb:PutItem.
                                        "Effect": "Allow",
                                        "Action": ["dynamodb:GetItem"],
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
            "RoleName": {"Value": {"Ref": "Role"}},
            "TableArn": {"Value": {"Fn::GetAtt": ["Table", "Arn"]}},
        },
    }

    stack_name, outputs = _deploy_stack(ctx, template, capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    api_id = outputs["ApiId"]
    table_name = outputs["TableName"]

    appsync = ctx.client("appsync")
    dynamodb = ctx.client("dynamodb")
    api_key = appsync.create_api_key(apiId=api_id, description="sim2real test key")["apiKey"]["id"]
    endpoint = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]["uris"]["GRAPHQL"]

    # Positive control: seed a row directly, then read it via the (permitted) GetItem
    # resolver, through the very same stack -- proves the deployment itself works.
    seed_id = ctx.unique_name("seed-")
    dynamodb.put_item(TableName=table_name, Item={"id": {"S": seed_id}, "val": {"S": "seed-value"}})
    ctx.on_cleanup(lambda: dynamodb.delete_item(TableName=table_name, Key={"id": {"S": seed_id}}))

    status, payload = _graphql_query(
        ctx, endpoint, api_key, "query Get($id: String!) { getItem(id: $id) { id val } }", {"id": seed_id}
    )
    assert status == 200 and "errors" not in payload, f"positive control (permitted read) failed: {payload}"
    assert payload["data"]["getItem"] == {"id": seed_id, "val": "seed-value"}

    # Negative: the resolver whose action the role does NOT permit fails at the data
    # plane, and the write does not land in DynamoDB.
    new_id = ctx.unique_name("denied-")
    status, payload = _graphql_query(
        ctx, endpoint,
        api_key,
        "mutation Put($id: String!, $val: String!) { putItem(id: $id, val: $val) { id val } }",
        {"id": new_id, "val": "should-not-persist"},
    )
    assert status == 200, f"unexpected transport-level failure: {status} {payload}"
    # Empirically (verified against real AWS), an unauthorized DynamoDB PutItem
    # surfaces as a null field value -- not necessarily a populated top-level
    # "errors" array -- so the field-not-populated half of the contract is the
    # portable assertion here. Accept either shape, but the field must be null.
    field_value = (payload.get("data") or {}).get("putItem")
    assert field_value is None, (
        f"expected the denied PutItem field to be null, got: {payload}"
    )

    row = dynamodb.get_item(TableName=table_name, Key={"id": {"S": new_id}}).get("Item")
    assert row is None, "PutItem should have been denied by IAM, but the row was written"

    # Restore: grant the withheld permission directly on the deployed role (same resource pin the
    # denied policy used) and demand the IDENTICAL mutation now succeeds -- proving the earlier
    # denial was this permission specifically, not a broken deployment or a stuck resolver.
    role_name = outputs["RoleName"]
    iam = ctx.client("iam")
    restore_policy_name = ctx.unique_name("sim2real-restore-put-item-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["dynamodb:PutItem"],
                        "Resource": outputs["TableArn"],
                    }
                ],
            }
        ),
    )

    restored_id = ctx.unique_name("restored-")
    ctx.on_cleanup(lambda: dynamodb.delete_item(TableName=table_name, Key={"id": {"S": restored_id}}))

    def _attempt_restored_put():
        return _graphql_query(
            ctx, endpoint,
            api_key,
            "mutation Put($id: String!, $val: String!) { putItem(id: $id, val: $val) { id val } }",
            {"id": restored_id, "val": "restored-value"},
        )

    deadline = time.monotonic() + 60.0
    restored_status, restored_payload = _attempt_restored_put()
    while (restored_payload.get("data") or {}).get("putItem") is None:
        if time.monotonic() >= deadline:
            raise AssertionError(
                "granting dynamodb:PutItem on the role never let the identical mutation succeed "
                f"within 60s (IAM propagation); last response: {restored_payload}"
            )
        time.sleep(3)
        restored_status, restored_payload = _attempt_restored_put()
    iam.delete_role_policy(RoleName=role_name, PolicyName=restore_policy_name)

    assert restored_status == 200 and "errors" not in restored_payload, (
        f"the identical mutation must succeed once the permission is granted: {restored_payload}"
    )
    assert restored_payload["data"]["putItem"] == {"id": restored_id, "val": "restored-value"}, (
        f"unexpected putItem echo after granting the permission: {restored_payload}"
    )

    restored_row = dynamodb.get_item(TableName=table_name, Key={"id": {"S": restored_id}}).get("Item")
    assert restored_row == {"id": {"S": restored_id}, "val": {"S": "restored-value"}}, (
        f"the restored write must land in DynamoDB, verified by an independent read: {restored_row}"
    )


# ===== helpers =====


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
    cfn.create_stack(**kwargs, Tags=[{"Key": "sim2real", "Value": CHECK}])
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
