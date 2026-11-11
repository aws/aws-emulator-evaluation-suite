"""cdk-restapi-cloudwatch-role-flag-governs-account-global-write."""
from __future__ import annotations

import json
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


CHECK = "cdk-restapi-cloudwatch-role-flag-governs-account-global-write"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 420.0
_SYNTH_TIMEOUT_S = 240.0
_HTTP_READY_DEADLINE_S = 180.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_restapi_flag"
_FLAG = "@aws-cdk/aws-apigateway:disableCloudWatchRole"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With the API Gateway CloudWatch-role feature flag omitted a `RestApi` synthesises an
    account-global `AWS::ApiGateway::Account`; with it enabled the deploy leaves that setting
    untouched and the stage still serves HTTPS.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    apigw = ctx.client("apigateway")

    stack = ctx.unique_name("sim2real-cdkapiflag-")
    marker = ctx.unique_name("marker-")
    base = {"account": account, "region": ctx.region, "stack_name": stack, "marker": marker}
    flag_on = {**base, _FLAG: "true"}
    # Omitted, not "false": a `--context` value is a CLI string and CDK's feature-flag read is
    # `!!context`, so "false" also reads as enabled. Only an absent key reaches the flag's default.
    flag_off = dict(base)

    work = _stage_app(ctx, _APP)
    logs = ctx.client("logs")
    state: dict[str, Any] = {"destroyed": False, "log_group": None}

    def _cleanup() -> None:
        # A completed `cdk destroy` has already removed the stack; the log group is never in it.
        group = state["log_group"]
        _teardown(ctx, [] if state["destroyed"] else [stack],
                  after=[("log group", lambda: _reap_log_group(logs, group))] if group else None)

    ctx.on_cleanup(_cleanup)

    # ---- 1. one context value, two resource sets, from the same source file ------------------
    _, _, with_role = _synth_doc(ctx, work, stack, flag_off, out="out-off",
                                 timeout_s=_SYNTH_TIMEOUT_S)
    _, _, without_role = _synth_doc(ctx, work, stack, flag_on, out="out-on",
                                    timeout_s=_SYNTH_TIMEOUT_S)
    with_counts = _type_counts(with_role)
    without_counts = _type_counts(without_role)
    assert with_counts.get("AWS::ApiGateway::Account") == 1, (
        f"with {_FLAG} omitted (the flag's default) the template holds "
        f"{with_counts.get('AWS::ApiGateway::Account')!r} AWS::ApiGateway::Account resources, "
        f"expected 1 — by default the RestApi L2 creates the account-global CloudWatch role. Full "
        f"type counts: {with_counts!r}"
    )
    assert "AWS::ApiGateway::Account" not in without_counts, (
        f"with {_FLAG}=true the template still holds an AWS::ApiGateway::Account resource; the "
        f"flag's entire purpose is to stop the RestApi L2 writing account-global state. Full "
        f"type counts: {without_counts!r}"
    )
    # The flag must change THAT and nothing else, or the two arms are not comparable.
    difference = {
        key: (with_counts.get(key), without_counts.get(key))
        for key in set(with_counts) | set(without_counts)
        if with_counts.get(key) != without_counts.get(key)
    }
    assert set(difference) == {"AWS::ApiGateway::Account", "AWS::IAM::Role"}, (
        f"toggling {_FLAG} changed the resource-type counts at {sorted(difference)!r}, expected "
        f"exactly {{'AWS::ApiGateway::Account', 'AWS::IAM::Role'}}; differences {difference!r}"
    )
    assert with_counts["AWS::IAM::Role"] == without_counts["AWS::IAM::Role"] + 1, (
        f"with the flag omitted there are {with_counts['AWS::IAM::Role']} IAM roles and with it "
        f"enabled {without_counts['AWS::IAM::Role']}; the flag should add exactly one role (the "
        f"CloudWatch role for the account resource)"
    )

    # ---- 2. deploy the SAFE arm, and prove the account-global setting never moves ------------
    before = _account_cloudwatch_role(apigw)
    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], flag_on,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    # Freeze detector: three consecutive reads must agree exactly. `None` (no role configured on
    # this account) is asserted just as strictly as an ARN — "absent throughout" is a value here.
    observations = [before] + [_account_cloudwatch_role(apigw) for _ in range(3)]
    assert len(set(observations)) == 1, (
        f"the account-global API Gateway CloudWatch role changed across the deploy: "
        f"{observations!r}. With {_FLAG}=true the stack must not emit "
        f"AWS::ApiGateway::Account, so nothing outside the stack may move"
    )

    outputs = _stack_outputs(ctx, stack)
    rest_api_id = outputs["RestApiId"]
    published_url = outputs["InvokeUrl"].rstrip("/")
    # Requests address the stage by API id and stage name; on AWS that is the published URL.
    invoke_url = ctx.api_url(rest_api_id, urllib.parse.urlsplit(published_url).path.strip("/"))
    stack_resources = [
        resource
        for page in ctx.client("cloudformation").get_paginator(
            "list_stack_resources").paginate(StackName=stack)
        for resource in page["StackResourceSummaries"]
    ]
    deployed_types = {resource["ResourceType"] for resource in stack_resources}
    assert "AWS::ApiGateway::Account" not in deployed_types, (
        f"the DEPLOYED stack contains an AWS::ApiGateway::Account resource ({deployed_types!r}) "
        f"even though its template did not — the target added account-global state the app never "
        f"asked for"
    )
    # The handler's own log group is not declared in the template, so CloudFormation never owns
    # it; `cdk destroy` leaves it behind. Delete it ourselves after the function is gone.
    functions = [
        resource["PhysicalResourceId"]
        for resource in stack_resources
        if resource["ResourceType"] == "AWS::Lambda::Function"
    ]
    assert len(functions) == 1, (
        f"the deployed stack lists AWS::Lambda::Function resources {functions!r}, expected "
        f"exactly one, the LambdaRestApi handler"
    )
    state["log_group"] = f"/aws/lambda/{functions[0]}"

    # ---- 3. TERMINAL READ: real HTTPS through the stage, with no CloudWatch role -------------
    status, payload = _http_until(ctx,
        invoke_url + "/", accept=(200,), deadline_s=_HTTP_READY_DEADLINE_S,
        reason="the API Gateway stage to begin serving after CREATE_COMPLETE",
    )
    answered = json.loads(payload)
    assert answered.get("marker") == marker, (
        f"GET through the deployed stage returned {status} {answered!r}, expected marker "
        f"{marker!r} — a RestApi deployed WITHOUT the account CloudWatch role must still serve "
        f"requests; the role is for access logging, not for request handling"
    )
    assert answered.get("method") == "GET", (
        f"the handler saw httpMethod {answered.get('method')!r}, expected 'GET' — the proxy "
        f"integration is not passing the request through faithfully"
    )

    # ---- teardown, asserted -----------------------------------------------------------------
    _cdk(ctx, work, ["destroy", stack, "--force"], flag_on,
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
    # The deleted stage does not settle to one deterministic answer at once: a 403, a transient
    # 500, and — once the per-API routing entry is withdrawn — a name-resolution failure all
    # occur within the same teardown window. The invariant that holds at every one of those
    # instants is that the stage never again serves 200.
    for _ in range(4):
        try:
            status, payload = _http(ctx, invoke_url + "/")
        except urllib.error.URLError as exc:
            status, payload = None, str(exc).encode()
        assert status != 200, (
            f"the stage URL of the deleted REST API {rest_api_id!r} answered 200 {payload!r} "
            f"after `cdk destroy`; a deleted stage must stop serving"
        )
    # And the account-global setting is still exactly where it started.
    after_destroy = _account_cloudwatch_role(apigw)
    assert after_destroy == before, (
        f"the account-global API Gateway CloudWatch role is {after_destroy!r} after teardown, "
        f"expected the value it had before this check ran, {before!r} — the destroy reset shared "
        f"state this check never should have touched"
    )


# ===== self-contained helpers =====


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


def _type_counts(template: dict[str, Any]) -> dict[str, int]:
    """How many resources of each type the template declares. Hard-subscripts `Resources`."""
    counts: dict[str, int] = {}
    for resource in template["Resources"].values():
        counts[resource["Type"]] = counts.get(resource["Type"], 0) + 1
    return counts


def _account_cloudwatch_role(apigw) -> str | None:
    """The ACCOUNT-AND-REGION-GLOBAL API Gateway CloudWatch role ARN, or None when unset.

    The field is absent on an account with no CloudWatch role configured, and the caller compares
    consecutive observations for equality, so `None` is a value the assertion can fail on.
    """
    role = apigw.get_account().get("cloudwatchRoleArn")
    return str(role) if role else None


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


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file.

    Deliberately an independent read: `--outputs-file` is written by the same process that did the
    deploy, so believing it would make the CLI both actor and witness.
    """
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
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
