"""cdk-restapi-added-method-forces-a-new-deployment-that-serves."""
from __future__ import annotations

import json
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "cdk-restapi-added-method-forces-a-new-deployment-that-serves"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 420.0
_SYNTH_TIMEOUT_S = 240.0
_DIFF_TIMEOUT_S = 300.0
_HTTP_READY_DEADLINE_S = 180.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_restapi_redeploy"
_DEPLOYMENT_TYPE = "AWS::ApiGateway::Deployment"
_DEPLOYMENT_ID_FORM = r"ApiDeploymentB17BE62D[0-9a-f]{32}"
_METHOD_A = "ApiaGET6504AF36"
_METHOD_B = "ApibGETD12D6B28"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Adding a method to a `RestApi` mints a NEW `Deployment` logical id, and the deployed stage
    really begins serving the new route — asserted over real HTTPS, both before and after, and
    confirmed independently from stack events (one Deployment created, one deleted).
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")

    stack = ctx.unique_name("sim2real-cdkapiredep-")
    marker = ctx.unique_name("marker-")
    base = {"account": account, "region": ctx.region, "stack_name": stack, "marker": marker}
    one_route = {**base, "routes": "one"}
    two_routes = {**base, "routes": "two"}

    work = _stage_app(ctx, _APP)
    logs = ctx.client("logs")
    state: dict[str, Any] = {"destroyed": False, "function_name": None}

    def _cleanup() -> None:
        # A completed `cdk destroy` has already removed the stack; the log group is never in it.
        fn_name = state["function_name"]
        _teardown(ctx, [] if state["destroyed"] else [stack], after=[
            ("log group", lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
        ] if fn_name else None)

    ctx.on_cleanup(_cleanup)

    # ---- the template-level relation, read at runtime, never pinned --------------------------
    _, _, first_template = _synth_doc(ctx, work, stack, one_route, out="out-one",
                                      timeout_s=_SYNTH_TIMEOUT_S)
    _, _, second_template = _synth_doc(ctx, work, stack, two_routes, out="out-two",
                                       timeout_s=_SYNTH_TIMEOUT_S)
    first_ids = sorted(_resources_of_type(first_template, _DEPLOYMENT_TYPE))
    second_ids = sorted(_resources_of_type(second_template, _DEPLOYMENT_TYPE))
    assert len(first_ids) == 1 and len(second_ids) == 1, (
        f"expected exactly one {_DEPLOYMENT_TYPE} in each template; one-route gave "
        f"{first_ids!r} and two-route gave {second_ids!r}"
    )
    first_deployment, second_deployment = first_ids[0], second_ids[0]
    # The L2 appends a hash of the API's configuration to the construct's logical id; the stack
    # events below show the two ids differ (one Deployment created, the other deleted).
    for deployment_id in (first_deployment, second_deployment):
        assert re.fullmatch(_DEPLOYMENT_ID_FORM, deployment_id), (
            f"the Deployment logical id {deployment_id!r} does not have the form "
            f"{_DEPLOYMENT_ID_FORM!r} (the Api construct's Deployment plus a configuration hash)"
        )
    first_methods = sorted(_resources_of_type(first_template, "AWS::ApiGateway::Method"))
    second_methods = sorted(_resources_of_type(second_template, "AWS::ApiGateway::Method"))
    assert (first_methods, second_methods) == (
            [_METHOD_A], [_METHOD_A, _METHOD_B]), (
        f"the one-route and two-route templates declare methods {first_methods!r} and "
        f"{second_methods!r}, expected [{_METHOD_A!r}] and [{_METHOD_A!r}, {_METHOD_B!r}] — the "
        f"second synth adds exactly the GET /b method"
    )
    function_ids = sorted(_resources_of_type(second_template, "AWS::Lambda::Function"))
    assert len(function_ids) == 1, (
        f"expected exactly one AWS::Lambda::Function in the template; got {function_ids!r}"
    )
    function_logical_id = function_ids[0]

    # ---- deploy one route, and establish the BEFORE state over real HTTPS --------------------
    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], one_route,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    # Read the function's physical name NOW, while the stack still exists: once the stack is
    # gone this lookup cannot resolve it, but the log group AWS creates for it is not a stack
    # resource and outlives the stack regardless.
    function_name = cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=function_logical_id)["StackResourceDetail"][
        "PhysicalResourceId"]
    state["function_name"] = function_name
    outputs = _stack_outputs(ctx, stack, "CREATE_COMPLETE")
    rest_api_id = outputs["RestApiId"]
    published_url = outputs["InvokeUrl"].rstrip("/")
    # Requests address the stage by API id and stage name; on AWS that is the published URL.
    invoke_url = ctx.api_url(rest_api_id, urllib.parse.urlsplit(published_url).path.strip("/"))
    assert outputs["RouteCount"] == "1", (
        f"the one-route deploy reports RouteCount={outputs['RouteCount']!r}, expected '1'"
    )

    status_a, body_a = _http_until(ctx,
        f"{invoke_url}/a", accept=(200,), deadline_s=_HTTP_READY_DEADLINE_S,
        reason="the API Gateway stage to begin serving /a after CREATE_COMPLETE",
    )
    assert json.loads(body_a).get("marker") == marker, (
        f"GET {invoke_url}/a returned {status_a} {body_a[:200]!r}, expected a body carrying "
        f"marker {marker!r}"
    )
    answer_b = _http(ctx, f"{invoke_url}/b")
    assert answer_b == (403, b'{"message":"Missing Authentication Token"}'), (
        f"GET {invoke_url}/b returned {answer_b!r} before /b was declared, expected API Gateway's "
        f"403 Missing Authentication Token for an undefined path on a REST API"
    )

    # ---- `cdk diff` must see the Deployment among the pending changes ------------------------
    rc, diff_output = _cdk(ctx, work, ["diff", stack, "--fail"], two_routes,
                           timeout_s=_DIFF_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk diff --fail` exited {rc} with a route added locally, expected 1; output tail: "
        f"{diff_output[-1000:]!r}"
    )
    assert _DEPLOYMENT_TYPE in diff_output, (
        f"`cdk diff` reported changes without naming {_DEPLOYMENT_TYPE}, so it does not show that "
        f"adding a method replaces the Deployment; output tail: {diff_output[-1200:]!r}"
    )

    # ---- deploy the second route, and demand the stage actually serves it --------------------
    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], two_routes,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    updated = _stack_outputs(ctx, stack, "UPDATE_COMPLETE")
    assert updated["RouteCount"] == "2", (
        f"after the update the stack reports RouteCount={updated['RouteCount']!r}, expected '2'"
    )
    assert updated["InvokeUrl"].rstrip("/") == published_url, (
        f"the invoke URL changed from {published_url!r} to "
        f"{updated['InvokeUrl'].rstrip('/')!r}; adding a method must not replace the REST API"
    )

    # TERMINAL READ: real HTTPS at the deployed stage, for the route that did not exist before.
    status_b2, body_b2 = _http_until(ctx,
        f"{invoke_url}/b", accept=(200,), deadline_s=_HTTP_READY_DEADLINE_S,
        reason=("the stage to be repointed at the NEW Deployment so /b becomes reachable — the "
                "whole property under test"),
    )
    answered = json.loads(body_b2)
    assert answered.get("marker") == marker, (
        f"GET {invoke_url}/b returned {status_b2} {answered!r} after the update, expected a body "
        f"carrying marker {marker!r}"
    )
    assert answered.get("path") == "/b", (
        f"the handler saw path {answered.get('path')!r} for a request to /b — the new method's "
        f"integration is not passing the request through faithfully"
    )
    # The old route must still work: replacing the Deployment must not drop configuration.
    status_a2, body_a2 = _http(ctx, f"{invoke_url}/a")
    assert status_a2 == 200 and json.loads(body_a2).get("marker") == marker, (
        f"GET {invoke_url}/a returned {status_a2} {body_a2[:200]!r} after the update, expected "
        f"200 with marker {marker!r} — the new Deployment dropped the pre-existing route"
    )

    # ---- the MECHANISM, from stack events rather than the CLI's rendering ---------------------
    events = _deployment_events(cfn, stack)
    assert (second_deployment, "CREATE_COMPLETE") in events, (
        f"stack events carry no CREATE_COMPLETE for the new Deployment {second_deployment!r}; "
        f"observed Deployment events {sorted(events)!r}"
    )
    assert (first_deployment, "DELETE_COMPLETE") in events, (
        f"stack events carry no DELETE_COMPLETE for the superseded Deployment "
        f"{first_deployment!r}; observed Deployment events {sorted(events)!r}. The update must "
        f"REPLACE the Deployment, not accumulate one"
    )
    new_deployment_id = cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=second_deployment)["StackResourceDetail"][
        "PhysicalResourceId"]
    live_stage = apigw.get_stage(restApiId=rest_api_id, stageName="prod")
    assert live_stage["deploymentId"] == new_deployment_id, (
        f"the prod stage publishes deploymentId {live_stage.get('deploymentId')!r}, expected "
        f"{new_deployment_id!r}, the physical id of the new Deployment {second_deployment!r}"
    )

    # ---- teardown, asserted -----------------------------------------------------------------
    _cdk(ctx, work, ["destroy", stack, "--force"], two_routes,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)
    state["destroyed"] = True
    _assert_stack_absent(ctx, stack)
    gone = _client_error(lambda: apigw.get_rest_api(restApiId=rest_api_id))
    assert gone.response["Error"]["Code"] == "NotFoundException", (
        f"GetRestApi on {rest_api_id!r} did not report NotFoundException after `cdk destroy`"
    )
    assert gone.response["Error"]["Message"] == (
        f"Invalid API identifier specified {account}:{rest_api_id}"
    ), gone.response["Error"]["Message"]


# ===== helpers =====


def _deployment_events(cfn, stack: str) -> set[tuple[str, str]]:
    """`(logical id, status)` for every `AWS::ApiGateway::Deployment` event on *stack*.

    Read from `DescribeStackEvents` so the mechanism is confirmed by CloudFormation rather than by
    the CDK CLI's own report of what it did.
    """
    seen: set[tuple[str, str]] = set()
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for event in page["StackEvents"]:
            if event.get("ResourceType") == _DEPLOYMENT_TYPE:
                seen.add((event["LogicalResourceId"], str(event.get("ResourceStatus"))))
    return seen


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present="
        f"{(source / 'app.py').is_file()}, cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`.

    `--no-version-reporting` drops the `AWS::CDK::Metadata` resource and CLI telemetry;
    `--no-color` keeps ANSI escapes out of any asserted output; `--ci` sends logs to stdout.
    """
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output tail: "
            f"{output[-1200:]!r}"
        )
    return result.returncode, output


def _synth_doc(ctx, work: Path, stack: str, context: dict[str, str], *, out: str,
               timeout_s: float) -> tuple[int, str, dict[str, Any]]:
    """Synthesise into `<work>/<out>`, asserting exit 0; return `(rc, output, parsed template)`."""
    shutil.rmtree(work / out, ignore_errors=True)
    rc, output = _cdk(ctx, work, ["synth", stack, "--output", out, "--quiet"], context,
                      timeout_s=timeout_s, expect_rc=0)
    template = work / out / f"{stack}.template.json"
    assert template.is_file(), (
        f"`cdk synth` exited {rc} but wrote no template at {template}; {out} contains "
        f"{sorted(p.name for p in (work / out).iterdir()) if (work / out).is_dir() else 'nothing'}"
    )
    return rc, output, json.loads(template.read_text())


def _resources_of_type(template: dict[str, Any], type_name: str) -> dict[str, Any]:
    """Every resource of *type_name*, keyed by logical id. Hard-subscripts `Resources` on purpose."""
    return {k: v for k, v in template["Resources"].items() if v["Type"] == type_name}


def _stack_outputs(ctx, stack: str, expected_status: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file.

    Deliberately an independent read: `--outputs-file` is written by the same process that did the
    deploy, so believing it would make the CLI both actor and witness.
    """
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == expected_status, (
        f"stack {stack!r} is {described['StackStatus']!r}, expected {expected_status} before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, url: str, *, method: str = "GET", body: bytes | None = None,
          timeout_s: float = 30.0) -> tuple[int, bytes]:
    """One real HTTPS request to the deployed API Gateway stage, returning `(status, body)`.

    `urllib` and not boto3 on purpose: this is the `dp:endpoint` leg. The request is unsigned and
    goes to `<api-id>.execute-api.<region>.amazonaws.com`, which is a hostname the AWS API model
    does not describe, so no signed-API transcript can express it.
    """
    request = _routed_request(ctx, url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s,
                                    context=_ssl_context(ctx.http_verify)) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is an ANSWER here, not a transport failure: several arms assert one.
        return exc.code, exc.read()


def _http_until(ctx, url: str, *, method: str = "GET", body: bytes | None = None,
                accept: tuple[int, ...] = (200,), deadline_s: float, reason: str,
                request_timeout_s: float = 30.0) -> tuple[int, bytes]:
    """Poll one URL until its status is in *accept*, raising on timeout.

    Needed because an API Gateway stage becomes reachable a few seconds after CloudFormation reports
    the Deployment complete; *reason* records what is being waited for so a later reader does not
    have to guess. The terminal set never contains a status the caller treats as failure.
    """
    deadline = time.monotonic() + deadline_s
    status, payload = -1, b""
    while time.monotonic() < deadline:
        status, payload = _http(ctx, url, method=method, body=body, timeout_s=request_timeout_s)
        if status in accept:
            return status, payload
        time.sleep(3.0)
    raise AssertionError(
        f"{method} {url} never returned a status in {accept!r} within {deadline_s}s while waiting "
        f"for {reason}; last status {status} body {payload[:300]!r}"
    )


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group *name* until *reads* consecutive reads find it absent; raise on budget."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name!r} still present after {budget_s}s of deletes")
        time.sleep(interval_s)


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        # Bounded: CloudFormation deletes are asynchronous with no notification channel.
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _assert_stack_absent(ctx, stack: str) -> None:
    """An independent read must report the stack gone with CloudFormation's specific code."""
    exc = _client_error(lambda: ctx.client("cloudformation").describe_stacks(StackName=stack))
    code = exc.response["Error"]["Code"]
    assert code == "ValidationError", (
        f"DescribeStacks on the deleted stack {stack!r} returned error code {code!r}, expected "
        f"'ValidationError'"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        f"DescribeStacks on the deleted stack {stack!r} raised ValidationError with message "
        f"{exc.response['Error']['Message']!r}"
    )


def _teardown(ctx, stacks: list[str], after: list[tuple[str, Any]] | None = None) -> None:
    """Delete each stack this run created, then run each after step; raise every failure."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps = [
        (f"stack {stack}", lambda s=stack: _delete_stack_and_wait(
            ctx, s, timeout_s=max(30.0, deadline - time.monotonic())))
        for stack in stacks
    ]
    steps += list(after or [])
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - every step runs; the failures are raised below
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
