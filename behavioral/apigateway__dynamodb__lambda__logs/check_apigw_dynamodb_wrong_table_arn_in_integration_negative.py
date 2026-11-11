"""apigw-dynamodb-wrong-table-arn-in-integration-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "apigw-dynamodb-wrong-table-arn-in-integration-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_REQUEST_TEMPLATE_PUT = """{
  "TableName": "__TABLE__",
  "Item": {
    "id": {"S": "$input.path('$.id')"},
    "value": {"S": "$input.path('$.value')"}
  }
}"""


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A request template that names a nonexistent DynamoDB table surfaces
    ResourceNotFoundException through the API and writes nothing; the same
    integration pointed at the real table succeeds."""
    table = _create_table(
        ctx,
        [{"AttributeName": "id", "KeyType": "HASH"}],
        [{"AttributeName": "id", "AttributeType": "S"}],
    )
    scan_before = ddb_scan_count(ctx, table["name"])
    assert scan_before == 0, f"expected a freshly created table to be empty, got {scan_before} items"

    # Resource="*" so the permission itself is never the reason for failure here --
    # only the bogus table name in the request template is under test.
    role_arn = _create_apigw_role(ctx, "*", ["dynamodb:PutItem"])
    api_id, root_id = _create_rest_api(ctx)

    bogus_table = ctx.unique_name("sim2real-missing-table-")
    bad_template = _REQUEST_TEMPLATE_PUT.replace("__TABLE__", bogus_table)
    good_template = _REQUEST_TEMPLATE_PUT.replace("__TABLE__", table["name"])
    # For a non-proxy AWS (HTTP-backend) integration, the selectionPattern is matched
    # against the backend-returned HTTP status code, not against exception text in the
    # body -- match broadly on "4\d{2}" and confirm the specific exception via the
    # execution log / raw passthrough body instead of relying on the pattern itself.
    integration_responses = [("200", None, None), ("400", r"4\d{2}", None)]

    resource_bad = _add_dynamodb_method(
        ctx, api_id, root_id, "badtable", "POST", "PutItem", role_arn,
        bad_template, integration_responses, ["200", "400"],
    )
    resource_good = _add_dynamodb_method(
        ctx, api_id, root_id, "goodtable", "POST", "PutItem", role_arn,
        good_template, integration_responses, ["200", "400"],
    )

    neg_id = ctx.unique_name("sim2real-neg-item-")
    neg_body = json.dumps({"id": neg_id, "value": "x"})
    # Poll to ride out any IAM-role-assumption propagation delay right after role
    # creation; the terminal condition under test is the mapped 4xx status.
    neg_result = _poll_until(
        lambda: _invoke(ctx, api_id, resource_bad, "POST", neg_body),
        lambda r: r["status"] == 400,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert neg_result["status"] == 400, neg_result["body"]
    combined = (neg_result["body"] or "") + (neg_result.get("log") or "")
    assert "ResourceNotFoundException" in combined, combined


    scan_after_negative = ddb_scan_count(ctx, table["name"])
    assert scan_after_negative == 0, "the real table must be unaffected by the bogus-table integration call"

    pos_id = ctx.unique_name("sim2real-pos-item-")
    pos_body = json.dumps({"id": pos_id, "value": "y"})
    pos_result = _poll_until(
        lambda: _invoke(ctx, api_id, resource_good, "POST", pos_body),
        lambda r: r["status"] == 200,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert pos_result["status"] == 200, pos_result["body"]
    ddb = ctx.client("dynamodb")
    got = ddb.get_item(TableName=table["name"], Key={"id": {"S": pos_id}})
    got_value = got.get("Item", {}).get("value", {}).get("S")
    assert got_value == "y", f"expected the positive-control write to persist value 'y', got {got_value!r}"


def _uname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"sim2real-apigwddb-{kind}-")


def _create_table(ctx, key_schema, attr_defs) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = _uname(ctx, "tbl")
    ddb.create_table(
        TableName=name,
        KeySchema=key_schema,
        AttributeDefinitions=attr_defs,
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return {"name": name, "arn": arn}


def ddb_scan_count(ctx, table_name: str) -> int:
    ddb = ctx.client("dynamodb")
    return ddb.scan(TableName=table_name)["Count"]


def _create_apigw_role(ctx, resource_arn: str, actions: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = _uname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "apigateway.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if actions:
        policy_name = _uname(ctx, "policy")
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource_arn}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_rest_api(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=_uname(ctx, "api"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _add_dynamodb_method(
    ctx,
    api_id: str,
    parent_id: str,
    path_part: str,
    http_method: str,
    action: str,
    role_arn: str,
    request_template: str,
    integration_responses: list[tuple[str, str | None, str | None]],
    method_status_codes: list[str],
) -> str:
    apigw = ctx.client("apigateway")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=parent_id, pathPart=path_part)["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE")
    uri = f"arn:aws:apigateway:{ctx.region}:dynamodb:action/{action}"
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="AWS",
        integrationHttpMethod="POST",
        uri=uri,
        credentials=role_arn,
        requestTemplates={"application/json": request_template},
        passthroughBehavior="NEVER",
    )
    for status_code, selection_pattern, resp_template in integration_responses:
        kwargs: dict[str, Any] = dict(
            restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode=status_code,
        )
        if selection_pattern is not None:
            kwargs["selectionPattern"] = selection_pattern
        if resp_template is not None:
            kwargs["responseTemplates"] = {"application/json": resp_template}
        apigw.put_integration_response(**kwargs)
    for status_code in method_status_codes:
        apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode=status_code)
    return resource_id


def _invoke(ctx, api_id: str, resource_id: str, http_method: str, body: str) -> dict[str, Any]:
    apigw = ctx.client("apigateway")
    resp = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        body=body,
        headers={"Content-Type": "application/json"},
    )
    return {"status": resp["status"], "body": resp["body"], "log": resp.get("log")}


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
