"""deploy-apigatewayv2-1-http-api-cors-removed-in-place-then-api-replaced."""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-1-http-api-cors-removed-in-place-then-api-replaced"
GROUP = "deploy"
SERVICES = ["apigatewayv2"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = DEPLOYMENTS / "http-api-lambda-cors-update-replace.yaml"

_ORIGIN = "https://allowed.example.com"
_MARKER = "sim2real-cfn-httpapi-ok"
_PREFLIGHT = {
    "Origin": _ORIGIN,
    "Access-Control-Request-Method": "GET",
    "Access-Control-Request-Headers": "content-type",
}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A stack update removing CorsConfiguration keeps the ApiId and turns CORS preflight off at the
    endpoint; repointing the Route at a new Api replaces it (new ApiId, old one NotFound, 404s).
    """
    ctx.verify_account_safety()
    assert _TEMPLATE.is_file(), f"the deploy artifact must exist on disk at {_TEMPLATE}"

    base = ctx.unique_name("sim2real-apigwv2-cfn-")
    params = {
        "ApiName": base,
        "FunctionName": f"{base}-fn",
        "RoleName": f"{base}-role",
        "AllowedOrigin": _ORIGIN,
    }
    agw = ctx.client("apigatewayv2")

    # Registered BEFORE the stack exists so LIFO runs it AFTER the stack (and its Lambda) is deleted.
    ctx.on_cleanup(lambda: _reap_lambda_log_group(ctx, f"/aws/lambda/{params['FunctionName']}"))

    # ---- create ------------------------------------------------------------------------------
    stack = _deploy_cfn(ctx, _TEMPLATE, stack_name=base, parameters=dict(params, Phase="cors"))
    stack_name = stack["stack_name"]
    api1 = stack["outputs"]["ApiIdOut"]
    assert stack["outputs"].get("ApiLogicalIdOut") == "CorsApi", (
        f"the create must provision the Api as logical id CorsApi, outputs: {stack['outputs']!r}"
    )
    got = agw.get_api(ApiId=api1)
    assert got.get("ProtocolType") == "HTTP", f"ProtocolType must be HTTP, got {got.get('ProtocolType')!r}"
    assert got.get("Description") == "sim2real phase cors", (
        f"Description must be the create-phase value, got {got.get('Description')!r}"
    )
    cors = got.get("CorsConfiguration") or {}
    assert cors.get("AllowOrigins") == [_ORIGIN] and cors.get("AllowMethods") == ["GET"], (
        f"GetApi must return the stack's CorsConfiguration, got {got.get('CorsConfiguration')!r}"
    )
    route1 = _physical_id(ctx, stack_name, "RouteA")

    url1 = _v2_invoke_url(ctx, got["ApiEndpoint"], "/a")
    status, hdrs, text = _poll_http(
        url1, accept=lambda s: s == 200, headers={"Origin": _ORIGIN},
        description="GET /a on the stack's $default AutoDeploy stage",
    )
    body = _json(text)
    assert body.get("marker") == _MARKER, f"GET /a must return the Lambda's body, got {text[:300]!r}"
    assert body.get("routeKey") == "GET /a", f"the Lambda must be reached via route 'GET /a', got {body!r}"
    assert body.get("version") == "2.0", (
        f"PayloadFormatVersion 2.0 must deliver a version '2.0' event to the Lambda, got {body!r}"
    )
    assert hdrs.get("access-control-allow-origin") == _ORIGIN, (
        f"a CORS-configured API must stamp access-control-allow-origin on the actual GET response, "
        f"got {hdrs.get('access-control-allow-origin')!r} (headers {sorted(hdrs)})"
    )

    status, hdrs, text = _http("OPTIONS", url1, headers=_PREFLIGHT)
    assert status == 204, f"a CORS preflight on a CORS-configured HTTP API must be 204, got {status}: {text!r}"
    assert hdrs.get("access-control-allow-origin") == _ORIGIN, (
        f"the preflight must echo the allowed origin, got {hdrs.get('access-control-allow-origin')!r}"
    )
    assert "GET" in (hdrs.get("access-control-allow-methods") or ""), (
        f"the preflight must allow GET, got {hdrs.get('access-control-allow-methods')!r}"
    )
    assert hdrs.get("access-control-max-age") == "300", (
        f"the preflight must carry MaxAge 300, got {hdrs.get('access-control-max-age')!r}"
    )

    # ---- update #1: Description changed, CorsConfiguration removed -- in place ----------------
    preview = _preview_changes(ctx, stack_name, _TEMPLATE, dict(params, Phase="nocors"))
    assert set(preview) == {"CorsApi"}, (
        f"update #1 must change ONLY the Api resource, the change set lists {preview!r}"
    )
    assert preview["CorsApi"]["action"] == "Modify" and preview["CorsApi"]["replacement"] == "False", (
        f"removing CORS and changing Description must be an in-place Modify (Replacement False), "
        f"the change set says {preview['CorsApi']!r}"
    )
    upd = _update_cfn(ctx, stack_name, _TEMPLATE, parameters=dict(params, Phase="nocors"))
    assert upd["outputs"]["ApiIdOut"] == api1, (
        f"an in-place update must keep the physical ApiId {api1!r}, the stack now reports "
        f"{upd['outputs']['ApiIdOut']!r}"
    )
    got = agw.get_api(ApiId=api1)
    assert got.get("Description") == "sim2real phase nocors", (
        f"update #1 must change Description in place, GetApi says {got.get('Description')!r}"
    )
    assert "CorsConfiguration" not in got, (
        f"removing CorsConfiguration from the template must remove it from the Api, GetApi still "
        f"returns {got.get('CorsConfiguration')!r}"
    )

    status, hdrs, text = _poll_http(
        url1, method="OPTIONS", headers=_PREFLIGHT, accept=lambda s: s != 204, timeout_s=120.0,
        description="the CORS preflight to stop being answered after CORS was removed",
    )
    assert status == 404, (
        f"with CORS removed and no OPTIONS route, a preflight must fall through to route matching "
        f"and 404, got {status}: {text[:200]!r}"
    )
    assert "access-control-allow-origin" not in hdrs, (
        f"a preflight must no longer be allowed, yet access-control-allow-origin="
        f"{hdrs.get('access-control-allow-origin')!r}"
    )
    status, hdrs, text = _http("GET", url1, headers={"Origin": _ORIGIN})
    assert status == 200 and _json(text).get("marker") == _MARKER, (
        f"the API must still serve GET /a after the in-place update, got {status}: {text[:300]!r}"
    )
    assert "access-control-allow-origin" not in hdrs, (
        f"GET /a must stop carrying CORS headers once CORS is removed, got "
        f"{hdrs.get('access-control-allow-origin')!r}"
    )

    # ---- update #2: the Route's ApiId repointed at a NEW Api -- replacement ------------------
    # A dependent cannot force its parent's replacement, so the Route (ApiId requires Replacement)
    # is repointed from CorsApi to a new ReplacementApi logical id.
    preview = _preview_changes(ctx, stack_name, _TEMPLATE, dict(params, Phase="replaced"))
    assert preview.get("CorsApi", {}).get("action") == "Remove", (
        f"update #2 must remove the old Api resource, the change set lists {preview!r}"
    )
    assert preview.get("ReplacementApi", {}).get("action") == "Add", (
        f"update #2 must add a new Api resource, the change set lists {preview!r}"
    )
    route_change = preview.get("RouteA") or {}
    assert route_change.get("action") == "Modify" and route_change.get("replacement") == "True", (
        f"repointing the Route's ApiId must replace the Route, the change set says {route_change!r}"
    )
    assert ("ApiId", "Always") in route_change.get("details", []), (
        f"the Route's replacement must be caused by ApiId (RequiresRecreation Always), details: "
        f"{route_change.get('details')!r}"
    )
    upd = _update_cfn(ctx, stack_name, _TEMPLATE, parameters=dict(params, Phase="replaced"))
    api2 = upd["outputs"]["ApiIdOut"]
    assert upd["outputs"].get("ApiLogicalIdOut") == "ReplacementApi", f"outputs: {upd['outputs']!r}"
    assert api2 != api1, f"update #2 must create a NEW Api, but the ApiId is still {api1!r}"
    route2 = _physical_id(ctx, stack_name, "RouteA")
    assert route2 != route1, (
        f"the Route must have been replaced (new physical id), it is still {route1!r}"
    )

    code, message = _error(lambda: agw.get_api(ApiId=api1))
    assert code == "NotFoundException", (
        f"the replaced Api {api1!r} must be deleted by the update's cleanup phase, GetApi gave {code!r}"
    )
    expected = f"Invalid API identifier specified {ctx.account}:{api1}"
    assert message == expected, f"GetApi on the replaced Api: message {message!r} != {expected!r}"
    got = agw.get_api(ApiId=api2)
    assert got.get("Description") == "sim2real phase replaced", (
        f"the new Api must carry the replacement Description, got {got.get('Description')!r}"
    )
    assert {r["RouteKey"] for r in agw.get_routes(ApiId=api2).get("Items") or []} == {"GET /a"}, (
        f"the replacement Route must live on the NEW Api, GetRoutes({api2!r}) says "
        f"{agw.get_routes(ApiId=api2).get('Items')!r}"
    )

    url2 = _v2_invoke_url(ctx, got["ApiEndpoint"], "/a")
    status, _, text = _poll_http(
        url2, accept=lambda s: s == 200, description="GET /a on the REPLACEMENT Api's endpoint",
    )
    assert _json(text).get("marker") == _MARKER and _json(text).get("routeKey") == "GET /a", (
        f"the replacement Api must serve the same Lambda through GET /a, got {text[:300]!r}"
    )
    status, _, text = _poll_http(
        url1, accept=lambda s: s == 404, timeout_s=300.0,
        description="the deleted Api's endpoint to stop routing (a 5xx is the teardown in flight)",
    )
    assert status == 404, (
        f"the deleted Api's hostname must stop routing (404), got {status}: {text[:200]!r}"
    )


def _json(text: str) -> dict:
    try:
        v = json.loads(text)
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def _error(fn) -> tuple:
    """(code, message) of the AWS error fn() raised. RAISES if fn() succeeded."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message", "<no message>")
    raise AssertionError(f"expected the call to fail, it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, {lower_header: value}, text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (resp.status, {k.lower(): v for k, v in resp.getheaders()},
                    resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in exc.headers.items()},
                exc.read().decode("utf-8", "replace"))


def _poll_http(url, *, accept, method="GET", headers=None, timeout_s=180.0, interval_s=3.0,
               description="invoke URL"):
    """Poll a URL until accept(status); return (status, headers, text). RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http(method, url, headers=headers)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, {}, f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({method} {url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _v2_invoke_url(ctx, api_endpoint, path):
    """The $default-stage invoke URL of an HTTP API."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, '$default')}/{p}"


def _reap_lambda_log_group(ctx, group: str) -> None:
    """Delete the function's log group in a bounded loop: a buffered flush can recreate it after
    the function is gone. The role grants no logs permissions, so normally there is nothing here."""
    logs = ctx.client("logs")
    for _ in range(3):
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups") or []
        if not any(g.get("logGroupName") == group for g in found):
            return
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(5)
    raise RuntimeError(f"log group {group} kept reappearing after deletion")


def _stack_status(ctx, stack_name):
    try:
        return ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0][
            "StackStatus"
        ]
    except ClientError:
        return "GONE"


def _delete_stack_and_wait(ctx, stack_name, *, timeout_s=600.0) -> None:
    """Teardown: delete the stack and wait; a failure raises."""
    try:
        ctx.client("cloudformation").delete_stack(StackName=stack_name)
        final = _poll_until(
            lambda: _stack_status(ctx, stack_name),
            lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
            timeout_s=timeout_s, interval_s=5.0, description=f"delete stack {stack_name}",
        )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(f"stack {stack_name} delete did not complete: {exc}") from exc
        return
    if final == "DELETE_FAILED":
        raise RuntimeError(f"stack {stack_name} ended DELETE_FAILED")


def _stack_parameters(parameters):
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()]


def _outputs(stack) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _deploy_cfn(ctx, template: Path, *, stack_name, parameters, timeout_s=600.0) -> dict[str, Any]:
    """Create a stack, register its teardown immediately, wait for CREATE_COMPLETE (else RAISE)."""
    cfn = ctx.client("cloudformation")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template.read_text(),
        Parameters=_stack_parameters(parameters),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, interval_s=5.0, description=f"stack {stack_name} create",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack_name} ended {stack['StackStatus']}: {stack.get('StackStatusReason')!r}"
    )
    return {"stack_name": stack_name, "stack_id": stack_id, "outputs": _outputs(stack)}


def _update_cfn(ctx, stack_name, template: Path, *, parameters, timeout_s=600.0) -> dict:
    """UpdateStack and wait for UPDATE_COMPLETE; any other terminal state RAISES, so a rollback is
    never mistaken for a successful update."""
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template.read_text(),
        Parameters=_stack_parameters(parameters),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, interval_s=5.0, description=f"stack {stack_name} update",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"stack {stack_name} update ended {stack['StackStatus']}: {stack.get('StackStatusReason')!r}"
    )
    return {"outputs": _outputs(stack)}


def _preview_changes(ctx, stack_name, template: Path, parameters) -> dict:
    """Create an UPDATE change set, read {logical_id: {action, replacement, details}}, delete it."""
    cfn = ctx.client("cloudformation")
    cs_name = ctx.unique_name("sim2real-preview-")
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=template.read_text(),
        Parameters=_stack_parameters(parameters),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        ChangeSetType="UPDATE",
    )
    try:
        desc = _poll_until(
            lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name),
            lambda d: d["Status"] in {"CREATE_COMPLETE", "FAILED"},
            timeout_s=180.0, interval_s=3.0, description=f"change set {cs_name}",
        )
        assert desc["Status"] == "CREATE_COMPLETE", (
            f"change set {cs_name} failed: {desc.get('StatusReason')!r}"
        )
        changes = list(desc.get("Changes") or [])
        token = desc.get("NextToken")
        while token:
            page = cfn.describe_change_set(
                StackName=stack_name, ChangeSetName=cs_name, NextToken=token
            )
            changes += page.get("Changes") or []
            token = page.get("NextToken")
    finally:
        cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name)
    out = {}
    for ch in changes:
        rc = ch.get("ResourceChange") or {}
        out[rc.get("LogicalResourceId")] = {
            "action": rc.get("Action"),
            "replacement": rc.get("Replacement"),
            "details": [
                ((d.get("Target") or {}).get("Name"), (d.get("Target") or {}).get("RequiresRecreation"))
                for d in rc.get("Details") or []
            ],
        }
    return out


def _physical_id(ctx, stack_name, logical_id) -> str:
    res = ctx.client("cloudformation").describe_stack_resource(
        StackName=stack_name, LogicalResourceId=logical_id
    )["StackResourceDetail"]
    return res["PhysicalResourceId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
