"""deploy-apigatewayv2-cfn-disable-execute-api-endpoint-blocks-default-domain."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-disable-execute-api-endpoint-blocks-default-domain"

GROUP = "deploy"

SERVICES = ["apigatewayv2", "cloudformation"]


def _template(disabled_name: str, enabled_name: str, upstream_url: str) -> str:
    def api(name: str, disable: bool) -> dict:
        return {
            "Type": "AWS::ApiGatewayV2::Api",
            "Properties": {
                "Name": name,
                "ProtocolType": "HTTP",
                "Target": upstream_url,
                "RouteKey": "ANY /",
                "DisableExecuteApiEndpoint": disable,
            },
        }

    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DisabledApi": api(disabled_name, True),
            "EnabledApi": api(enabled_name, False),
        },
        "Outputs": {
            "DisabledApiId": {"Value": {"Ref": "DisabledApi"}},
            "EnabledApiId": {"Value": {"Ref": "EnabledApi"}},
        },
    })


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation ``AWS::ApiGatewayV2::Api`` with ``DisableExecuteApiEndpoint: true`` answers
    404 Not Found on its default domain, while a twin in the same
    stack with the flag false serves the upstream's token."""
    ctx.verify_account_safety()
    upstream, token = _mock_backend(ctx)

    disabled_name = ctx.unique_name("sim2real-xsvc-disexec-off-")
    enabled_name = ctx.unique_name("sim2real-xsvc-disexec-on-")
    stack = _deploy_cfn(
        ctx,
        _template(disabled_name, enabled_name, upstream),
        stack_name=ctx.unique_name("sim2real-xsvc-disexec-stk-"),
    )
    outputs = stack["outputs"]

    agw = ctx.client("apigatewayv2")
    disabled = agw.get_api(ApiId=outputs["DisabledApiId"])
    assert disabled.get("DisableExecuteApiEndpoint") is True, (
        f"GetApi for the stack's DisabledApi must report DisableExecuteApiEndpoint=True, got "
        f"{disabled.get('DisableExecuteApiEndpoint')!r}"
    )
    enabled = agw.get_api(ApiId=outputs["EnabledApiId"])
    assert enabled.get("DisableExecuteApiEndpoint") is False, (
        f"GetApi for the stack's EnabledApi must report DisableExecuteApiEndpoint=False, got "
        f"{enabled.get('DisableExecuteApiEndpoint')!r}"
    )

    enabled_endpoint = ctx.stage_url(enabled["ApiEndpoint"], "$default")
    disabled_endpoint = ctx.api_url(outputs["DisabledApiId"], "$default")

    status, text = _poll_http(
        enabled_endpoint + "/",
        accept=lambda s: s == 200,
        description="the enabled twin's default execute-api domain",
    )
    assert status == 200 and text == token, (
        f"the enabled twin must proxy through to the upstream token {token!r} on its default "
        f"domain, got {status}: {text[:300]!r}"
    )

    status, text = _http("GET", disabled_endpoint + "/")
    assert status == 404, (
        f"the disabled twin's default domain must answer 404, got {status}: {text[:300]!r}"
    )
    assert json.loads(text) == {"message": "Not Found"}, (
        f"the disabled twin's refusal body must be the standard Not Found envelope, got "
        f"{text[:300]!r}"
    )


def _http(method, url, timeout_s=20):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _poll_http(url, *, accept, timeout_s=180.0, interval_s=4.0, description="invoke URL"):
    deadline = time.monotonic() + timeout_s
    last = (None, "")
    while True:
        try:
            last = _http("GET", url)
        except OSError as exc:
            last = (None, f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[1][:300]!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack_status(ctx, stack_name):
    try:
        return ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0][
            "StackStatus"
        ]
    except ClientError as exc:
        if "does not exist" in exc.response.get("Error", {}).get("Message", ""):
            return "GONE"
        raise


def _delete_stack_and_wait(ctx, stack_name, *, timeout_s=300.0) -> None:
    ctx.client("cloudformation").delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template_body: str, *, stack_name: str, timeout_s: float = 300.0) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name, timeout_s=timeout_s))
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name} reaching a terminal create state",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(
            f"stack {stack_name} ended in {stack['StackStatus']}: "
            f"{stack.get('StackStatusReason', '(no reason given)')}"
        )
    return {
        "stack_name": stack_name,
        "outputs": {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])},
    }


def _mock_backend(ctx) -> tuple[str, str]:
    """A REST API MOCK stage answering ANY / with 200 and a run-unique token: the quick-create
    Target, so the reachable twin's response comes from this check's own backend."""
    ag = ctx.client("apigateway")
    token = ctx.unique_name("sim2real-xsvc-disexec-token-")
    rest_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-disexec-backend-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real:managed": "true"},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, rest_id))
    root = next(r["id"] for r in ag.get_resources(restApiId=rest_id)["items"] if r["path"] == "/")
    ag.put_method(restApiId=rest_id, resourceId=root, httpMethod="ANY", authorizationType="NONE")
    ag.put_integration(
        restApiId=rest_id, resourceId=root, httpMethod="ANY", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=rest_id, resourceId=root, httpMethod="ANY", statusCode="200")
    ag.put_integration_response(
        restApiId=rest_id, resourceId=root, httpMethod="ANY", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": token},
    )
    ag.create_deployment(restApiId=rest_id, stageName="backend")
    return ctx.rest_api_url(rest_id, "backend"), token


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
