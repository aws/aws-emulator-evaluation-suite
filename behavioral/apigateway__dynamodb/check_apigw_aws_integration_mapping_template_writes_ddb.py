"""apigw-aws-integration-mapping-template-writes-ddb."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-aws-integration-mapping-template-writes-ddb"

GROUP = "data-format"

SERVICES = ["apigateway", "dynamodb"]


# The VTL request template; __TABLE__ is substituted at wiring time. $input.path(...)
# reads the client's JSON body and $context.* are gateway-supplied request variables.
_REQUEST_TEMPLATE = """{
  "TableName": "__TABLE__",
  "Item": {
    "pk": {"S": "$input.path('$.id')"},
    "note": {"S": "$input.path('$.note')"},
    "ctxRequestId": {"S": "$context.requestId"},
    "ctxStage": {"S": "$context.stage"},
    "ctxMethod": {"S": "$context.httpMethod"}
  }
}"""

_RESPONSE_TEMPLATE = '{"stored": true, "requestId": "$context.requestId"}'


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A REST `AWS` integration writes to DynamoDB through a VTL request template and maps the reply
    through a response template: the returned requestId equals the persisted ctxRequestId, so
    `$context` is evaluated in both templates on a real invoke of the deployed stage."""
    table = _create_ddb_table(ctx, kind="mappingtpl")
    role = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["dynamodb:PutItem"],
                    "Resource": table["arn"],
                }
            ],
        },
    )

    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw-mappingtpl")
    res_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")[
        "id"
    ]
    ag.put_method(
        restApiId=api_id, resourceId=res_id, httpMethod="POST", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="POST",
        type="AWS",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{ctx.region}:dynamodb:action/PutItem",
        credentials=role["arn"],
        passthroughBehavior="NEVER",
        requestTemplates={
            "application/json": _REQUEST_TEMPLATE.replace("__TABLE__", table["name"])
        },
    )
    ag.put_method_response(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="POST",
        statusCode="200",
        responseModels={"application/json": "Empty"},
    )
    ag.put_integration_response(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="POST",
        statusCode="200",
        responseTemplates={"application/json": _RESPONSE_TEMPLATE},
    )
    _deploy_stage(ctx, api_id, "test")

    item_id = ctx.unique_name("mapped-")
    status, _, text = _poll_http(
        _rest_invoke_url(ctx, api_id, "test", "/items"),
        accept=lambda s: s == 200,
        method="POST",
        body=json.dumps({"id": item_id, "note": "mapped-by-vtl"}).encode(),
        headers={"Content-Type": "application/json"},
        timeout_s=180.0,
        description="AWS non-proxy DynamoDB integration",
    )
    assert status == 200, (
        f"expected 200 from the AWS non-proxy DynamoDB integration, got {status}: {text}"
    )
    payload = json.loads(text)
    assert payload.get("stored") is True, (
        f"integration response template did not render; got {text!r}"
    )
    response_request_id = payload.get("requestId") or ""
    assert response_request_id and "$context" not in response_request_id, (
        f"$context.requestId was not evaluated in the integration RESPONSE template; "
        f"got {response_request_id!r}"
    )

    item = _poll_until(
        lambda: _ddb_item(ctx, table["name"], item_id),
        lambda i: i is not None,
        timeout_s=45.0,
        interval_s=2.0,
        description=f"DynamoDB item {item_id!r} written by the mapping template",
    )
    assert item["note"]["S"] == "mapped-by-vtl", (
        f"$input.path('$.note') did not reach DynamoDB; got {item!r}"
    )
    assert item["ctxStage"]["S"] == "test", (
        f"$context.stage should be 'test', got {item['ctxStage']['S']!r}"
    )
    assert item["ctxMethod"]["S"] == "POST", (
        f"$context.httpMethod should be 'POST', got {item['ctxMethod']['S']!r}"
    )
    assert item["ctxRequestId"]["S"] == response_request_id, (
        f"$context.requestId differs between the request template "
        f"({item['ctxRequestId']['S']!r}) and the response template "
        f"({response_request_id!r}) — the two templates did not see one request context"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result.

    Raises AssertionError on timeout. Propagation (IAM, stage deploy, log delivery) is
    always waited out this way — never with a bare time.sleep as the assertion.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _stays_absent(
    probe, predicate, *, window_s=25.0, interval_s=2.5, description="effect"
):
    """Assert predicate(probe()) stays FALSY for a whole bounded window.

    The negative-delivery shape: an effect that must NEVER appear is observed over a
    settle window, not with one racy read that could pass simply by being early.
    """
    deadline = time.monotonic() + window_s
    while True:
        last = probe()
        assert not predicate(last), (
            f"{description} appeared but must NOT have (delivery was suppressed "
            f"upstream). Observed: {last!r}"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


def _http(method, url, body=None, headers=None, timeout_s=20):
    """HTTP request via urllib (stdlib only). Returns (status, lower-cased headers, text).

    A 4xx/5xx is a RESULT, not an exception — negative checks assert on the status and
    body of the error response, so HTTPError is unwrapped rather than raised.
    """
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as e:
        return (
            e.code,
            {k.lower(): v for k, v in e.headers.items()},
            e.read().decode("utf-8", "replace"),
        )


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=150.0,
    interval_s=3.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status) is true; return (status, headers, text).

    Stage/deployment/execute-api-DNS propagation is real and measured in seconds, so the
    first request through a freshly deployed stage is polled to a CONDITION with a bounded
    deadline. Connection-level errors (DNS/TLS still settling) are retried, not raised.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 - execute-api DNS/TLS settling
            last = (None, {}, "connection error")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} {url} never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:400]!r}"
    )


def _rest_invoke_url(ctx, api_id, stage, path):
    """The invoke URL of a DEPLOYED REST API stage, from ``ctx.rest_api_url``.

    Real AWS: ``https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>``; under an
    emulator, the ``/_aws/execute-api/<id>/<stage>/<path>`` route (see ctx.rest_api_url).
    """
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _create_rest_api(ctx, kind="api", **extra):
    """Create a REGIONAL REST API (teardown registered) and return (api_id, root_resource_id)."""
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=_xname(ctx, kind),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=_xsvc_resource_tags(),
        **extra,
    )["id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage, variables=None, **extra):
    """CreateDeployment + CreateStage. Returns the deployment id.

    Deployment and stage are separate on purpose: several checks put two stages on ONE
    deployment to isolate a per-stage setting as the only variable.
    """
    ag = ctx.client("apigateway")
    dep_id = ag.create_deployment(restApiId=api_id)["id"]
    kwargs = {"restApiId": api_id, "stageName": stage, "deploymentId": dep_id}
    if variables:
        kwargs["variables"] = variables
    kwargs.update(extra)
    ag.create_stage(**kwargs)
    ctx.on_cleanup(
        lambda: ctx.client("apigateway").delete_stage(restApiId=api_id, stageName=stage)
    )
    return dep_id


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust_service, inline_policy=None, managed_policies=None):
    """Create an IAM role and register its (policies-first) teardown. Returns {name,arn}.

    IAM propagation is real: the caller must still tolerate the first use of a brand-new
    role failing (see _create_function_with_retry / the apigateway credentials retries).
    """
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_ddb_table(ctx, kind="table", key="pk"):
    """Create an on-demand DynamoDB table with a single STRING hash key. Returns {name,arn}.

    DynamoDB keys are ALWAYS typed in this file: {"pk": {"S": "v"}} — in the check and in
    every inline Lambda handler source.
    """
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, kind)
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=90.0,
        interval_s=2.0,
        description=f"DynamoDB table {name} ACTIVE",
    )
    return {"name": name, "arn": resp["TableDescription"]["TableArn"], "key": key}


def _ddb_item(ctx, table, key_value, key="pk"):
    """GetItem (consistent read) or None."""
    got = ctx.client("dynamodb").get_item(
        TableName=table, Key={key: {"S": key_value}}, ConsistentRead=True
    )
    return got.get("Item")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
