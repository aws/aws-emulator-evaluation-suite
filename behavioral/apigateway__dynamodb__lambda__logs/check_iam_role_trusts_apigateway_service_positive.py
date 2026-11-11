"""iam-role-trusts-apigateway-service-positive."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "iam-role-trusts-apigateway-service-positive"
GROUP = "trust-policy"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A role trusting apigateway.amazonaws.com lets API Gateway assume it for a DynamoDB AWS integration."""
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    apigw = ctx.client("apigateway")
    region = ctx.region

    table_name = ctx.unique_name("sim2real-apigw-ddb-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    role_name = ctx.unique_name("sim2real-apigw-trust-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy("apigateway.amazonaws.com"),
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "ddb-put"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    api_id, item_url = _build_dynamodb_integration_api(
        ctx, apigw, table_name, role_arn, "good", region
    )

    item_id = ctx.unique_name("item-")
    status, _ = _poll_http_get(f"{item_url}/{item_id}", 200, timeout_s=90.0)
    assert status == 200, f"expected 200 from API Gateway->DynamoDB integration, got {status}"

    got = ddb.get_item(TableName=table_name, Key={"id": {"S": item_id}})
    assert "Item" in got, "PutItem via API Gateway AWS integration did not persist to DynamoDB"
    persisted_id = got["Item"]["id"]["S"]
    assert persisted_id == item_id, f"expected persisted id {item_id!r}, got {persisted_id!r}"


def _trust_policy(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _wait_table_active(ddb, table_name, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _build_dynamodb_integration_api(ctx, apigw, table_name, role_arn, path_part, region):
    """Wires GET /<path_part>/{id} -> AWS integration PutItem on table_name using role_arn."""
    api = apigw.create_rest_api(name=ctx.unique_name(f"sim2real-apigw-{path_part}-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    branch = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=path_part)
    id_res = apigw.create_resource(restApiId=api_id, parentId=branch["id"], pathPart="{id}")
    resource_id = id_res["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        requestParameters={"method.request.path.id": True},
    )
    template = json.dumps({"TableName": table_name, "Item": {"id": {"S": "$input.params('id')"}}})
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{region}:dynamodb:action/PutItem",
        credentials=role_arn,
        requestTemplates={"application/json": template},
        passthroughBehavior="WHEN_NO_TEMPLATES",
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )
    apigw.create_deployment(restApiId=api_id, stageName="test")

    item_url = f"{ctx.rest_api_url(api_id, 'test')}/{path_part}"
    return api_id, item_url


def _http_get(url, timeout=10.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _poll_http_get(url, expect_status, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = (None, b"")
    while time.monotonic() < deadline:
        status, body = _http_get(url)
        last = (status, body)
        if status == expect_status:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
