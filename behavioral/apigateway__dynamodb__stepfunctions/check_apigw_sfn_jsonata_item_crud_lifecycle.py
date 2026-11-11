"""apigw-sfn-jsonata-item-crud-lifecycle."""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-sfn-jsonata-item-crud-lifecycle"
GROUP = "data-format"
SERVICES = ["apigateway", "dynamodb", "stepfunctions"]

_XSVC_PREFIX = "sim2real-xsvc-"


def _definition(table: str) -> dict:
    """A JSONata-mode state machine that routes on `$states.input.op` to a direct DynamoDB
    SDK integration per CRUD verb, with no Lambda in the data path."""
    return {
        "QueryLanguage": "JSONata",
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Condition": "{% $states.input.op = 'create' %}", "Next": "Create"},
                    {"Condition": "{% $states.input.op = 'read' %}", "Next": "Read"},
                    {"Condition": "{% $states.input.op = 'update' %}", "Next": "Update"},
                    {"Condition": "{% $states.input.op = 'delete' %}", "Next": "Delete"},
                    {"Condition": "{% $states.input.op = 'list' %}", "Next": "List"},
                ],
                "Default": "Unknown",
            },
            "Create": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:putItem",
                "Arguments": {
                    "TableName": table,
                    "Item": {
                        "id": {"S": "{% $states.input.id %}"},
                        "name": {"S": "{% $states.input.name %}"},
                        "value": {"S": "{% $states.input.value %}"},
                    },
                },
                "Output": "{% $states.input %}",
                "End": True,
            },
            "Read": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:getItem",
                "Arguments": {"TableName": table, "Key": {"id": {"S": "{% $states.input.id %}"}}},
                "Output": (
                    "{% $exists($states.result.Item) ? "
                    '{"found": true, "id": $states.input.id, '
                    '"name": $states.result.Item.name.S, "value": $states.result.Item.value.S} '
                    ': {"found": false} %}'
                ),
                "End": True,
            },
            "Update": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:updateItem",
                "Arguments": {
                    "TableName": table,
                    "Key": {"id": {"S": "{% $states.input.id %}"}},
                    "UpdateExpression": "SET #n = :n, #v = :v",
                    "ExpressionAttributeNames": {"#n": "name", "#v": "value"},
                    "ExpressionAttributeValues": {
                        ":n": {"S": "{% $states.input.name %}"},
                        ":v": {"S": "{% $states.input.value %}"},
                    },
                },
                "Output": '{% {"updated": true} %}',
                "End": True,
            },
            "Delete": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:deleteItem",
                "Arguments": {"TableName": table, "Key": {"id": {"S": "{% $states.input.id %}"}}},
                "Output": '{% {"deleted": true} %}',
                "End": True,
            },
            "List": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:dynamodb:scan",
                "Arguments": {"TableName": table},
                "Output": '{% {"ids": $states.result.Items.id.S} %}',
                "End": True,
            },
            "Unknown": {"Type": "Fail", "Error": "UnknownOp"},
        },
    }


# The SyncExecution output (JSON on success, by construction above) is the whole response body.
def _request_template(op: str, *, from_body=(), from_path=()) -> str:
    fields = [f'\\"op\\":\\"{op}\\"']
    for name in from_path:
        fields.append(f'\\"{name}\\":\\"$util.escapeJavaScript($input.params(\'{name}\'))\\"')
    for name in from_body:
        fields.append(f'\\"{name}\\":\\"$util.escapeJavaScript($input.path(\'$.{name}\'))\\"')
    body = "{" + ",".join(fields) + "}"
    return '{"stateMachineArn": "__SM__", "input": "' + body + '"}'


_RESPONSE_TEMPLATE = "$input.path('$.output')"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:representation",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """REST API methods on /items call StartSyncExecution on a JSONata Express state machine doing
    DynamoDB CRUD via SDK integrations: create, read, update, list and delete an item, then confirm
    a read and a list after the delete no longer see it."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    sm_arn = _create_state_machine(ctx, _definition(table))
    role = _create_role(ctx, "apigateway.amazonaws.com",
                         inline_policy=_allow(["states:StartSyncExecution"], sm_arn))
    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, "sfn-crudl")
    items_id = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    item_id = _c(ag.create_resource, restApiId=api_id, parentId=items_id, pathPart="{id}")["id"]

    uri = f"arn:aws:apigateway:{ctx.region}:states:action/StartSyncExecution"
    _wire_method(ctx, ag, api_id, items_id, "POST", role["arn"], uri,
                 _request_template("create", from_body=("id", "name", "value")), sm_arn)
    _wire_method(ctx, ag, api_id, items_id, "GET", role["arn"], uri,
                 _request_template("list"), sm_arn)
    _wire_method(ctx, ag, api_id, item_id, "GET", role["arn"], uri,
                 _request_template("read", from_path=("id",)), sm_arn)
    _wire_method(ctx, ag, api_id, item_id, "PUT", role["arn"], uri,
                 _request_template("update", from_path=("id",), from_body=("name", "value")), sm_arn)
    _wire_method(ctx, ag, api_id, item_id, "DELETE", role["arn"], uri,
                 _request_template("delete", from_path=("id",)), sm_arn)

    _deploy_stage(ctx, api_id, "live")
    base = _rest_invoke_url(ctx, api_id, "live", "/items")
    hdrs = {"Content-Type": "application/json"}
    item_id_value = ctx.unique_name("item-")

    status, _h, text = _poll_http(
        base, method="POST", headers=hdrs,
        body=json.dumps({"id": item_id_value, "name": "Widget", "value": "blue"}).encode(),
        accept=lambda s, t: s == 200, description="create")
    assert status == 200, f"create expected 200, got {status}: {text[:300]!r}"
    assert item_id_value in text, f"create response must echo the new id, got {text!r}"

    st, _, text = _http("GET", f"{base}/{item_id_value}", headers=hdrs)
    assert st == 200, f"read expected 200, got {st}: {text[:300]!r}"
    assert "Widget" in text and "blue" in text, f"read did not surface the stored fields: {text!r}"

    st, _, text = _http("PUT", f"{base}/{item_id_value}",
                        body=json.dumps({"name": "Widget Pro", "value": "green"}).encode(),
                        headers=hdrs)
    assert st == 200, f"update expected 200, got {st}: {text[:300]!r}"

    st, _, text = _http("GET", f"{base}/{item_id_value}", headers=hdrs)
    assert st == 200, f"post-update read expected 200, got {st}: {text[:300]!r}"
    assert "Widget Pro" in text and "green" in text, (
        f"post-update read must reflect the update, got {text!r}")
    assert "blue" not in text, f"post-update read must not still carry the old value: {text!r}"

    st, _, text = _http("GET", base, headers=hdrs)
    assert st == 200, f"list expected 200, got {st}: {text[:300]!r}"
    assert item_id_value in text, f"list must include the created item, got {text!r}"

    st, _, text = _http("DELETE", f"{base}/{item_id_value}", headers=hdrs)
    assert st == 200, f"delete expected 200, got {st}: {text[:300]!r}"

    st, _, text = _http("GET", f"{base}/{item_id_value}", headers=hdrs)
    assert st == 200, f"read-after-delete expected 200, got {st}: {text[:300]!r}"
    assert '"found":false' in text.replace(" ", ""), (
        f"read-after-delete must report found:false, got {text!r}")
    assert "Widget" not in text, f"read-after-delete must not leak the deleted item: {text!r}"

    st, _, text = _http("GET", base, headers=hdrs)
    assert st == 200, f"post-delete list expected 200, got {st}: {text[:300]!r}"
    assert item_id_value not in text, f"post-delete list must no longer include the item: {text!r}"


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _xsvc_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-"), "sim2real": CHECK}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_tags().items()]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _c(fn, **kw):
    """Call an apigateway control-plane op, retrying only its per-account mutation throttle."""
    for attempt in range(10):
        try:
            return fn(**kw)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException" or attempt == 9:
                raise
            time.sleep(min(4.0, 0.3 * (2 ** attempt)))
    raise RuntimeError("unreachable")


def _create_table(ctx, ddb):
    name = _xname(ctx, "table")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}]}
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                            Path="/sim2real/", Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                            PolicyDocument=json.dumps(inline_policy))
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _allow(actions, resource):
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}]}


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(f"iam role {role_name}: {exc}") from exc


def _create_state_machine(ctx, definition):
    """A JSONata-mode EXPRESS state machine under a fresh role with the DynamoDB permissions it
    needs, retrying CreateStateMachine while the new role is not yet assumable."""
    sfn = ctx.client("stepfunctions")
    table = definition["States"]["Create"]["Arguments"]["TableName"]
    table_arn = ctx.client("dynamodb").describe_table(TableName=table)["Table"]["TableArn"]
    role = _create_role(ctx, "states.amazonaws.com", inline_policy=_allow(
        ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem",
         "dynamodb:DeleteItem", "dynamodb:Scan"], table_arn))
    name = _xname(ctx, "sfn-crudl-sm")
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role["arn"],
                type="EXPRESS", tags=[{"key": k, "value": v} for k, v in _xsvc_tags().items()],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if ("not authorized to assume" not in str(exc)
                    and "assume the provided role" not in str(exc)) or time.monotonic() > deadline:
                raise
            time.sleep(4)
    ctx.on_cleanup(lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=arn))
    return arn


def _delete_rest_api(ctx, api_id):
    """DeleteRestApi is rate-limited account-wide; retry the throttle, never swallow it."""
    ag = ctx.client("apigateway")
    deadline = time.monotonic() + 150
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() > deadline:
                raise RuntimeError(f"rest api {api_id}: {code}") from exc
            time.sleep(8)


def _create_rest_api(ctx, kind):
    ag = ctx.client("apigateway")
    api_id = _c(ag.create_rest_api, name=_xname(ctx, kind),
                endpointConfiguration={"types": ["REGIONAL"]}, tags=_xsvc_tags())["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ctx, api_id))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _wire_method(ctx, ag, api_id, resource_id, http_method, role_arn, uri, request_template, sm_arn):
    _c(ag.put_method, restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
       authorizationType="NONE")
    _c(ag.put_integration, restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
       type="AWS", integrationHttpMethod="POST", uri=uri, credentials=role_arn,
       passthroughBehavior="NEVER",
       requestTemplates={"application/json": request_template.replace("__SM__", sm_arn)})
    _c(ag.put_method_response, restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
       statusCode="200")
    _c(ag.put_integration_response, restApiId=api_id, resourceId=resource_id,
       httpMethod=http_method, statusCode="200",
       responseTemplates={"application/json": _RESPONSE_TEMPLATE})


def _deploy_stage(ctx, api_id, stage):
    ag = ctx.client("apigateway")
    dep_id = _c(ag.create_deployment, restApiId=api_id)["id"]
    _c(ag.create_stage, restApiId=api_id, stageName=stage, deploymentId=dep_id)
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_stage(restApiId=api_id, stageName=stage))
    return dep_id


def _rest_invoke_url(ctx, api_id, stage, path):
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _http(method, url, body=None, headers=None, timeout_s=30):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return (e.code, {k.lower(): v for k, v in e.headers.items()},
                e.read().decode("utf-8", "replace"))


def _poll_http(url, *, accept, method="GET", body=None, headers=None, timeout_s=240.0,
               interval_s=4.0, description="invoke URL"):
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except Exception as exc:  # noqa: BLE001 - execute-api DNS/TLS settling
            last = (None, {}, f"connection error: {exc!r}")
        else:
            if accept(last[0], last[2]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(f"{description} {url} never reached an accepted response within "
                         f"{timeout_s}s. Last: {last[0]} {last[2][:400]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
