"""iam-role-wrong-trust-principal-apigateway-negative."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "iam-role-wrong-trust-principal-apigateway-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A role whose trust policy excludes apigateway.amazonaws.com blocks the AWS-integration PutItem call."""
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    apigw = ctx.client("apigateway")
    region = ctx.region

    table_name = ctx.unique_name("sim2real-apigw-badtrust-ddb-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    # role has the RIGHT dynamodb permissions but the WRONG trust principal (ec2, not apigateway)
    bad_role_name = ctx.unique_name("sim2real-apigw-badtrust-")
    bad_role = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=_trust_policy("ec2.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    bad_role_arn = bad_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))

    # role with the correct trust principal, same permissions -> the positive control
    good_role_name = ctx.unique_name("sim2real-apigw-goodtrust-")
    good_role = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=_trust_policy("apigateway.amazonaws.com"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    good_role_arn = good_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))

    ddb_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}
            ],
        }
    )
    for role_name in (bad_role_name, good_role_name):
        iam.put_role_policy(
            RoleName=role_name, PolicyName="ddb-put", PolicyDocument=ddb_policy
        )
        ctx.on_cleanup(
            lambda rn=role_name: iam.delete_role_policy(
                RoleName=rn, PolicyName="ddb-put"
            )
        )

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-badtrust-api-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    bad_url = _wire_branch(
        ctx, apigw, api_id, root_id, "bad", table_name, bad_role_arn, region
    )
    good_url = _wire_branch(
        ctx, apigw, api_id, root_id, "good", table_name, good_role_arn, region
    )
    apigw.create_deployment(restApiId=api_id, stageName="test")

    # --- negative branch: role cannot be assumed by API Gateway ---
    bad_item_id = ctx.unique_name("bad-item-")
    status, _ = _poll_http_get_until_stable(
        f"{bad_url}/{bad_item_id}", 500, timeout_s=90.0
    )
    assert status == 500, (
        f"expected 500 from an unassumable-role AWS integration, got {status}"
    )

    absent = ddb.get_item(TableName=table_name, Key={"id": {"S": bad_item_id}})
    assert "Item" not in absent, (
        "PutItem must NOT have persisted when the role trust was wrong"
    )

    # --- positive control: same wiring, correctly-trusted role ---
    good_item_id = ctx.unique_name("good-item-")
    status, _ = _poll_http_get(f"{good_url}/{good_item_id}", 200, timeout_s=90.0)
    assert status == 200, (
        f"expected 200 from the correctly-trusted control integration, got {status}"
    )

    present = ddb.get_item(TableName=table_name, Key={"id": {"S": good_item_id}})
    assert "Item" in present, (
        "PutItem via the correctly-trusted control role should have persisted"
    )



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


def _wire_branch(ctx, apigw, api_id, root_id, path_part, table_name, role_arn, region):
    branch = apigw.create_resource(
        restApiId=api_id, parentId=root_id, pathPart=path_part
    )
    id_res = apigw.create_resource(
        restApiId=api_id, parentId=branch["id"], pathPart="{id}"
    )
    resource_id = id_res["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        requestParameters={"method.request.path.id": True},
    )
    template = json.dumps(
        {"TableName": table_name, "Item": {"id": {"S": "$input.params('id')"}}}
    )
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
    return f"{ctx.rest_api_url(api_id, 'test')}/{path_part}"


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


def _poll_http_get_until_stable(
    url, expect_status, timeout_s=90.0, interval_s=3.0, stable_hits=2
):
    """Polls until `expect_status` is observed `stable_hits` times in a row (rules out a transient
    5xx during deployment propagation masquerading as the real rejection)."""
    deadline = time.monotonic() + timeout_s
    hits = 0
    last = (None, b"")
    while time.monotonic() < deadline:
        status, body = _http_get(url)
        last = (status, body)
        if status == expect_status:
            hits += 1
            if hits >= stable_hits:
                return last
        else:
            hits = 0
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
