"""sam-implicit-api-synthesis-serves-real-https."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-implicit-api-synthesis-serves-real-https"

GROUP = "deploy-sam-transform"

SERVICES = ["apigateway", "cloudformation", "lambda"]

# SAM leaves this uri as an unresolved Fn::Sub in the Processed template, and it hardcodes
# `arn:aws:apigateway` rather than using ${AWS::Partition}.
_INTEGRATION_URI = (
    "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${Fn.Arn}/invocations"
)

_DEPLOYMENT_ID_RE = re.compile(r"^ServerlessRestApiDeployment[0-9a-f]{10}$")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A SAM function with Api events and no declared API synthesizes a REST API serving real HTTPS.

    The endpoint is gated on the synthesized Lambda permission: removing it turns GET into a 500.
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    awslambda = ctx.client("lambda")

    function_name = _xname(ctx, "sam-api-fn")
    nonce = uuid.uuid4().hex

    # Registered BEFORE the deploy so LIFO runs it AFTER the stack delete: Lambda creates
    # /aws/lambda/<name> on first invocation and CloudFormation never owns it, so
    # DELETE_COMPLETE leaves the group behind.
    ctx.on_cleanup(
        lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{function_name}")
    )

    template = json.dumps(_template(function_name, nonce))
    change_set = _create_change_set(ctx, template)
    assert change_set["Status"] == "CREATE_COMPLETE", (
        "the SAM transform rejected a valid document: "
        f"{change_set['Status']!r} / {change_set.get('StatusReason')!r}"
    )

    # The synthesis is computed at TRANSFORM time -- every one of these exists in the change set
    # before a single resource has been created.
    planned = sorted(
        c["ResourceChange"]["LogicalResourceId"] for c in change_set.get("Changes", [])
    )
    deployments = [lid for lid in planned if lid.startswith("ServerlessRestApiDeployment")]
    assert len(deployments) == 1 and _DEPLOYMENT_ID_RE.match(deployments[0]), (
        "SAM synthesizes exactly one content-hash-suffixed implicit-API deployment; the change "
        f"set planned {deployments!r}"
    )
    assert planned == sorted([
        "Fn", "FnRole", "FnGetPermissionProd", "FnPostPermissionProd", "FnItemPermissionProd",
        "ServerlessRestApi", deployments[0], "ServerlessRestApiProdStage",
    ]), (
        "three Api events must plan a RestApi, a Deployment, a Prod Stage and one Permission "
        f"per method -- nothing more and nothing less. Change set planned {planned!r}"
    )

    stack_name = change_set["stack_name"]
    _execute_change_set(ctx, stack_name, change_set["change_set_name"])

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    # A template may Ref a resource it never declared: the implicit API's logical id is a
    # documented contract, so this Output resolving at all is itself the assertion.
    api_id = outputs["ApiId"]
    assert api_id, f"Ref ServerlessRestApi resolved to nothing; outputs were {outputs!r}"
    function_arn = outputs["FnArn"]

    processed = _template_body(cfn, stack_name, "Processed")
    original = _template_body(cfn, stack_name, "Original")
    assert "AWS::Serverless::Function" in json.dumps(original), (
        "the Original projection must be the body as submitted, transform and all"
    )
    assert "AWS::ApiGateway::RestApi" not in json.dumps(original), (
        "the Original projection must not contain the synthesized API"
    )
    assert "AWS::Serverless::" not in json.dumps(processed), (
        "no AWS::Serverless:: type may survive into the Processed projection"
    )
    body = processed["Resources"]["ServerlessRestApi"]["Properties"]["Body"]
    assert body["swagger"] == "2.0", (
        "SAM generates the implicit API as an OpenAPI 2.0 document, not as "
        f"ApiGateway::Resource/Method resources; got swagger {body.get('swagger')!r}"
    )
    assert sorted(body["paths"]) == ["/items", "/items/{id}"], (
        f"the generated paths must be exactly the declared routes; got {sorted(body['paths'])!r}"
    )
    assert sorted(body["paths"]["/items"]) == ["get", "post"], (
        f"/items must carry exactly the two declared methods; got {sorted(body['paths']['/items'])!r}"
    )
    integration = body["paths"]["/items"]["get"]["x-amazon-apigateway-integration"]
    assert integration["type"] == "aws_proxy", (
        f"the generated integration must be aws_proxy; got {integration.get('type')!r}"
    )
    assert integration["httpMethod"] == "POST", (
        "the aws_proxy integration method is POST even for a GET route -- it is the INTEGRATION "
        f"method, not the route method. Got {integration.get('httpMethod')!r}"
    )
    assert integration["uri"] == {"Fn::Sub": _INTEGRATION_URI}, (
        "the integration uri must be the unresolved Fn::Sub SAM emits, hardcoding the aws "
        f"partition; got {integration.get('uri')!r}"
    )

    # SAM's deployment swap leaves a second `Stage` stage on the same deployment as `Prod`.
    stages = {s["stageName"]: s for s in apigw.get_stages(restApiId=api_id)["item"]}
    assert sorted(stages) == ["Prod", "Stage"], (
        "SAM's implicit API carries exactly two stages: the servable `Prod` and the `Stage` "
        f"stage its deployment resource declares. Got {sorted(stages)!r}"
    )
    assert stages["Prod"]["deploymentId"] == stages["Stage"]["deploymentId"], (
        "both stages must point at the one synthesized deployment; got "
        f"{stages['Prod']['deploymentId']!r} vs {stages['Stage']['deploymentId']!r}"
    )

    # SourceArns use a wildcard stage segment despite the logical id reading `...PermissionProd`.
    statements = json.loads(awslambda.get_policy(FunctionName=function_name)["Policy"])["Statement"]
    assert len(statements) == 3, (
        f"one Lambda permission per Api event, so three statements; got {len(statements)}"
    )
    by_arn = {}
    for stmt in statements:
        assert stmt["Principal"] == {"Service": "apigateway.amazonaws.com"}, (
            f"a synthesized Api permission must trust API Gateway; got {stmt['Principal']!r}"
        )
        assert stmt["Action"] == "lambda:InvokeFunction", (
            f"got action {stmt['Action']!r}"
        )
        assert stmt["Resource"] == function_arn, (
            f"permission points at {stmt['Resource']!r}, not the synthesized function {function_arn!r}"
        )
        by_arn[stmt["Condition"]["ArnLike"]["AWS:SourceArn"]] = stmt
    account = _account_id(ctx)
    prefix = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}"
    assert sorted(by_arn) == sorted([
        f"{prefix}/*/GET/items", f"{prefix}/*/POST/items", f"{prefix}/*/GET/items/*",
    ]), (
        "each SourceArn must scope to this API and this method path, with a WILDCARD stage "
        "segment and the literal arn:aws:execute-api partition -- an emulator that writes `Prod` "
        f"or ${{AWS::Partition}} diverges. Got {sorted(by_arn)!r}"
    )
    get_items_sid = by_arn[f"{prefix}/*/GET/items"]["Sid"]
    assert "FnGetPermissionProd" in get_items_sid, (
        f"Lambda's statement id is derived from the CFN logical id; got {get_items_sid!r}"
    )

    base = _apigw_url(ctx, api_id, "Prod")
    status, headers, text = _poll_http(
        "GET", base + "items", lambda s, h, t: s == 200,
        description="GET /Prod/items on the SAM-synthesized stage",
    )
    payload = json.loads(text)
    assert payload["nonce"] == nonce, (
        f"the body must be computed by the deployed handler; got {text[:300]!r}"
    )
    assert payload["httpMethod"] == "GET", f"proxy event httpMethod was {payload['httpMethod']!r}"
    assert payload["stage"] == "Prod", (
        f"requestContext.stage must be Prod; got {payload['stage']!r}"
    )
    assert headers.get("x-sim2real-probe") == nonce, (
        f"the handler's custom response header must reach the wire; headers were {headers!r}"
    )

    status, _, text = _http("GET", base + "items/abc123")
    assert status == 200, f"GET /Prod/items/abc123 returned {status}: {text[:300]!r}"
    assert json.loads(text)["pathParameters"] == {"id": "abc123"}, (
        "path-parameter extraction from the synthesized {id} route must reach the event; got "
        f"{text[:300]!r}"
    )

    status, _, text = _http("POST", base + "items", body='{"hi":"there"}')
    assert status == 200, f"POST /Prod/items returned {status}: {text[:300]!r}"
    posted = json.loads(text)
    assert posted["body"] == '{"hi":"there"}', (
        f"the request body must reach the handler verbatim; got {posted['body']!r}"
    )
    assert posted["isBase64Encoded"] is False, (
        f"a text body must not be base64-flagged; got {posted['isBase64Encoded']!r}"
    )

    for method, path in (("DELETE", "items"), ("PUT", "nope")):
        status, _, text = _http(method, base + path)
        assert status == 403, (
            f"{method} /Prod/{path} was never declared, so API Gateway must refuse it with 403; "
            f"got {status} {text[:200]!r}"
        )
        assert json.loads(text)["message"] == "Missing Authentication Token", (
            f"{method} /Prod/{path} refusal body was {text[:200]!r}"
        )
    status, _, _ = _http("GET", base + "items")
    assert status == 200, (
        f"control: the declared GET on the same API must still answer 200; got {status}"
    )

    awslambda.remove_permission(FunctionName=function_name, StatementId=get_items_sid)
    status, _, text = _poll_http(
        "GET", base + "items", lambda s, h, t: s != 200,
        timeout_s=180.0,
        description="GET /Prod/items after the synthesized GET permission was removed",
    )
    assert status == 500, (
        "with the synthesized permission gone, API Gateway cannot invoke the function and must "
        f"return 500; got {status} {text[:200]!r}"
    )
    assert json.loads(text)["message"] == "Internal server error", (
        f"the unauthorized-integration body was {text[:200]!r}"
    )
    status, _, text = _http("POST", base + "items", body='{"a":1}')
    assert status == 200, (
        "control: the POST permission was untouched, so that method must still answer 200; got "
        f"{status} {text[:200]!r}"
    )
    assert json.loads(text)["nonce"] == nonce, f"control POST body was {text[:200]!r}"

    # Restoring the permission shows the 500 was caused by the permission alone.
    awslambda.add_permission(
        FunctionName=function_name,
        StatementId=get_items_sid,
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"{prefix}/*/GET/items",
    )
    status, _, text = _poll_http(
        "GET", base + "items", lambda s, h, t: s == 200,
        description="GET /Prod/items after the synthesized GET permission was restored",
    )
    restored = json.loads(text)
    assert restored["nonce"] == nonce, (
        f"the restored call must reach the same handler; got {text[:300]!r}"
    )
    assert restored["httpMethod"] == "GET", (
        f"the restored call must be the same route; got {restored['httpMethod']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

_HANDLER = (
    "import json\n"
    "NONCE = {nonce!r}\n"
    "def handler(event, context):\n"
    "    return {{'statusCode': 200,\n"
    "            'headers': {{'x-sim2real-probe': NONCE,\n"
    "                        'Content-Type': 'application/json'}},\n"
    "            'body': json.dumps({{'nonce': NONCE,\n"
    "                                'httpMethod': event.get('httpMethod'),\n"
    "                                'path': event.get('path'),\n"
    "                                'pathParameters': event.get('pathParameters'),\n"
    "                                'stage': event.get('requestContext', {{}}).get('stage'),\n"
    "                                'body': event.get('body'),\n"
    "                                'isBase64Encoded': event.get('isBase64Encoded')}})}}\n"
)


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _template(function_name: str, nonce: str) -> dict:
    """One Serverless::Function, three Api events, and NO API resource declared anywhere."""
    return {
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Fn": {"Type": "AWS::Serverless::Function", "Properties": {
                "FunctionName": function_name,
                "Handler": "index.handler",
                "Runtime": "python3.12",
                "InlineCode": _HANDLER.format(nonce=nonce),
                "Events": {
                    "Get": {"Type": "Api", "Properties": {"Path": "/items", "Method": "get"}},
                    "Post": {"Type": "Api", "Properties": {"Path": "/items", "Method": "post"}},
                    "Item": {"Type": "Api",
                             "Properties": {"Path": "/items/{id}", "Method": "get"}},
                },
            }},
        },
        # Ref-ing a resource the template never declared: only the transform can make this resolve.
        "Outputs": {"ApiId": {"Value": {"Ref": "ServerlessRestApi"}},
                    "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}}},
    }


def _template_body(cfn, stack_name: str, stage: str) -> dict:
    """get_template returns a dict for a JSON template and a string for YAML; normalise."""
    body = cfn.get_template(StackName=stack_name, TemplateStage=stage)["TemplateBody"]
    return json.loads(body) if isinstance(body, str) else body


def _http(method: str, url: str, *, body=None, headers=None):
    """One request; an HTTP error status is a result, not an exception."""
    request = urllib.request.Request(
        url, method=method, data=body.encode() if body else None,
        headers=headers or ({"Content-Type": "application/json"} if body else {}),
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:  # noqa: S310 - fixed scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())


def _apigw_url(ctx, api_id: str, stage: str) -> str:
    """Invoke URL for a deployed stage, with a trailing slash."""
    return f"{ctx.rest_api_url(api_id, stage)}/"


def _poll_http(method, url, predicate, *, body=None, timeout_s=180.0, interval_s=3.0,
               description="stage response"):
    """Re-issue a request until predicate(status, headers, text) holds.

    A REST API stage becomes servable asynchronously, and a permission change takes a few
    seconds to be honoured, so both are polled to a condition with a bounded deadline rather
    than slept through."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, headers, text = _http(method, url, body=body)
        if predicate(status, headers, text):
            return status, headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last was "
                f"{status} {text[:200]!r}"
            )
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    """Best-effort log-group teardown; a group Lambda never created is not an error."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=900.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(_status, lambda s: s in {"DELETE_COMPLETE", "GONE"}, timeout_s=timeout_s,
                interval_s=5.0, description=f"delete stack {stack_name}")


def _create_change_set(ctx, template_body: str, *, timeout_s=300.0) -> dict:
    """Create a CREATE change set with the SAM capabilities and poll it to a terminal status.

    The change set is what shows the transform's output BEFORE anything is created. The stack
    teardown is registered here, before the change set exists, so a REVIEW_IN_PROGRESS shell
    stack is never left behind either."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    stack_name = _xname(ctx, "stk")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName="sim2real-cs1",
        ChangeSetType="CREATE",
        TemplateBody=template_body,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"],
    )
    described = _poll_until(
        lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName="sim2real-cs1"),
        lambda d: d["Status"] in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"change set for {stack_name}",
    )
    described["stack_name"] = stack_name
    described["change_set_name"] = "sim2real-cs1"
    return described


def _execute_change_set(ctx, stack_name: str, change_set_name: str, *, timeout_s=900.0) -> None:
    """Execute a change set and wait for CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cfn.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith(("_COMPLETE", "_FAILED")),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name}",
    )
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in {status!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
