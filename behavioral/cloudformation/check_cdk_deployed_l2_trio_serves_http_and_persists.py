"""cdk-deployed-l2-trio-serves-http-and-persists."""
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


CHECK = "cdk-deployed-l2-trio-serves-http-and-persists"
GROUP = "deploy"
SERVICES = ["cloudformation"]

# Declared phase budgets; their SUM must stay under the 1800 s suite ceiling.
_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 420.0
_HTTP_READY_DEADLINE_S = 180.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_trio"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CDK Function + Table + LambdaRestApi app deploys and serves: an HTTPS POST lands a Table
    row, an unwritten key reads back null, and after `cdk destroy` every resource reports not-found.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    ddb = ctx.client("dynamodb")
    lam = ctx.client("lambda")
    apigw = ctx.client("apigateway")

    stack = ctx.unique_name("sim2real-cdktrio-")
    written_key = ctx.unique_name("key-")
    absent_key = ctx.unique_name("nokey-")
    marker = ctx.unique_name("marker-")
    app_context = {"account": account, "region": ctx.region, "stack_name": stack}

    work = _stage_app(ctx, _APP)
    logs = ctx.client("logs")
    state: dict[str, Any] = {"destroyed": False, "log_group": None}

    def _cleanup() -> None:
        # A completed `cdk destroy` has already removed the stack; the log group is never in it.
        group = state["log_group"]
        _teardown(ctx, [] if state["destroyed"] else [stack],
                  after=[("log group", lambda: _reap_log_group(logs, group))] if group else None)

    ctx.on_cleanup(_cleanup)

    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], app_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = _stack_outputs(ctx, stack)
    for key in ("TableName", "FunctionName", "RestApiId", "InvokeUrl"):
        assert key in outputs, (
            f"the deployed stack's Outputs are {sorted(outputs)!r}, expected to include {key!r} "
            f"— the CDK app declares a CfnOutput for it"
        )
    table_name = outputs["TableName"]
    fn_name = outputs["FunctionName"]
    rest_api_id = outputs["RestApiId"]
    published_url = outputs["InvokeUrl"].rstrip("/")
    # Requests address the stage by API id and stage name; on AWS that is the published URL.
    invoke_url = ctx.api_url(rest_api_id, urllib.parse.urlsplit(published_url).path.strip("/"))
    # The handler's own log group is not declared in the template, so CloudFormation never owns
    # it; `cdk destroy` leaves it behind. Delete it ourselves after the function is gone.
    state["log_group"] = f"/aws/lambda/{fn_name}"

    # The invoke URL must be the prod stage of the API this stack created: HTTPS, a host whose
    # first label is the API id, and the stage path. The requests below prove it serves.
    parts = urllib.parse.urlsplit(outputs["InvokeUrl"])
    url_shape = (parts.scheme, parts.hostname.split(".")[0], parts.path)
    assert url_shape == ("https", rest_api_id, "/prod/"), (
        f"the stack's InvokeUrl {outputs['InvokeUrl']!r} has (scheme, first host label, path) "
        f"{url_shape!r}, expected ('https', {rest_api_id!r}, '/prod/') — the L2's `api.url` is "
        f"not addressing this API's prod stage"
    )

    # ---- the only write in this check comes from a real, unsigned HTTPS request -------------
    # It crosses the L2-wired route, Lambda permissions, role grant and TABLE env variable.
    request_body = json.dumps({"op": "put", "key": written_key, "marker": marker}).encode()
    status, payload = _http_until(ctx,
        invoke_url + "/", method="POST", body=request_body, accept=(200,),
        deadline_s=_HTTP_READY_DEADLINE_S,
        reason="the API Gateway stage to begin serving after CREATE_COMPLETE",
    )
    answered = json.loads(payload)
    assert answered == {"wrote": written_key}, (
        f"POST through the deployed stage returned {status} {answered!r}, expected "
        f"{{'wrote': {written_key!r}}} — the AWS_PROXY integration did not reach the function "
        f"the RestApi L2 was given"
    )

    # ---- TERMINAL READ: at the Table, via an operation the request never issued -------------
    item = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": written_key}}, ConsistentRead=True
    ).get("Item")
    assert item is not None, (
        f"GetItem on {table_name!r} found no row at pk={written_key!r} after the HTTP request "
        f"returned 200 — the function ran but its DynamoDB write did not land, so the "
        f"grant_read_write_data the Table L2 generated is not effective"
    )
    assert item.get("marker", {}).get("S") == marker, (
        f"the row at pk={written_key!r} carries marker "
        f"{item.get('marker', {}).get('S')!r}, expected {marker!r}"
    )

    # ---- the same path, asked about a key nobody wrote, must answer with an absence ---------
    _, absent_payload = _http(ctx,
        invoke_url + "/", method="POST",
        body=json.dumps({"op": "get", "key": absent_key}).encode(),
    )
    assert json.loads(absent_payload) == {"marker": None}, (
        f"asking the deployed API for the never-written key {absent_key!r} returned "
        f"{json.loads(absent_payload)!r}, expected {{'marker': None}} — a target that answers "
        f"the marker for every key would pass the read above and fail here"
    )

    # ---- the Function is also reachable directly, and sees the same row ---------------------
    direct = _invoke(lam, fn_name, {"op": "get", "key": written_key})
    assert direct == {"marker": marker}, (
        f"invoking {fn_name!r} directly for pk={written_key!r} returned {direct!r}, expected "
        f"{{'marker': {marker!r}}}"
    )

    # ---- the {proxy+} ANY route sends any path to the handler, which fails on an empty body --
    unmatched = invoke_url + "/" + ctx.unique_name("nopath-")
    unmatched_answer = _http(ctx, unmatched)
    assert unmatched_answer == (502, b'{"message": "Internal server error"}'), (
        f"GET {unmatched} returned {unmatched_answer!r}, expected the 502 API Gateway returns "
        f"when the proxy-integrated handler raises on a body-less request"
    )

    # ---- destroy, then prove gone AND unusable, resource by resource -----------------------
    # The app sets removal_policy=DESTROY; the DynamoDB L2 default would RETAIN the table.
    _cdk(ctx, work, ["destroy", stack, "--force"], app_context,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)
    state["destroyed"] = True

    _assert_stack_absent(ctx, stack)
    gone_table = _client_error(lambda: ddb.describe_table(TableName=table_name))
    assert gone_table.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"DescribeTable on {table_name!r} did not report ResourceNotFoundException after "
        f"`cdk destroy` — the table with DeletionPolicy: Delete survived"
    )
    assert gone_table.response["Error"]["Message"] == (
        f"Requested resource not found: Table: {table_name} not found"
    ), gone_table.response["Error"]["Message"]
    zombie = _client_error(
        lambda: ddb.put_item(TableName=table_name,
                             Item={"pk": {"S": ctx.unique_name("zombie-")}})
    )
    assert zombie.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"PutItem on the deleted table {table_name!r} did not report "
        f"ResourceNotFoundException — a delete that leaves a WRITABLE table behind is not a "
        f"delete"
    )
    assert zombie.response["Error"]["Message"] == "Requested resource not found", (
        zombie.response["Error"]["Message"]
    )
    gone_fn = _client_error(lambda: lam.get_function(FunctionName=fn_name))
    assert gone_fn.response["Error"]["Code"] == "ResourceNotFoundException", (
        f"GetFunction on {fn_name!r} did not report ResourceNotFoundException after "
        f"`cdk destroy`"
    )
    assert gone_fn.response["Error"]["Message"] == (
        f"Function not found: arn:aws:lambda:{ctx.region}:{account}:function:{fn_name}"
    ), gone_fn.response["Error"]["Message"]
    gone = _client_error(lambda: apigw.get_rest_api(restApiId=rest_api_id))
    assert gone.response["Error"]["Code"] == "NotFoundException", (
        f"GetRestApi on {rest_api_id!r} did not report NotFoundException after `cdk destroy`"
    )
    assert gone.response["Error"]["Message"] == (
        f"Invalid API identifier specified {account}:{rest_api_id}"
    ), gone.response["Error"]["Message"]
    # The stage URL must stop serving too — the resource being gone from the control plane and
    # the endpoint still answering would be a divergence the control-plane reads cannot see.
    # A deleted stage answers 403, a transient 500, or stops resolving within the same window;
    # what holds at every instant is that it never again serves 200.
    for _ in range(4):
        try:
            gone_status, gone_body = _http(ctx, invoke_url + "/", method="POST", body=request_body)
        except urllib.error.URLError as exc:
            gone_status, gone_body = None, str(exc).encode()
        assert gone_status != 200, (
            f"the stage URL of the deleted REST API {rest_api_id!r} answered 200 {gone_body!r} "
            f"after `cdk destroy`; a deleted stage must stop serving"
        )

# ===== self-contained helpers =====


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo.

    A missing app is a defect of this check, so this asserts rather than creating anything.
    """
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
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`. `--no-version-reporting`
    drops the CDK::Metadata resource, `--no-color` strips ANSI escapes, `--ci` logs to stdout.
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


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's
    `--outputs-file`, so the process that deployed is not also the witness.
    """
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _invoke(lam, fn_name: str, event: dict[str, Any]) -> Any:
    """Invoke and decode, treating a handler error as a failure rather than a payload."""
    response = lam.invoke(FunctionName=fn_name, Payload=json.dumps(event).encode())
    body = response["Payload"].read()
    assert "FunctionError" not in response, (
        f"invoking {fn_name!r} raised {response.get('FunctionError')!r}: {body[:400]!r}"
    )
    return json.loads(body)


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, url: str, *, method: str = "GET", body: bytes | None = None,
          timeout_s: float = 30.0) -> tuple[int, bytes]:
    """One unsigned HTTPS request to the deployed API Gateway stage, returning `(status, body)`.

    `urllib`, not boto3: the `execute-api` stage URL is not an AWS API operation.
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
    """Poll one URL until its status is in *accept*, raising on timeout. An API Gateway stage
    becomes reachable a few seconds after CloudFormation reports the Deployment complete.
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


def _teardown(ctx, stacks: list[str], extra: list[tuple[str, Any]] | None = None,
              after: list[tuple[str, Any]] | None = None) -> None:
    """Run each extra, delete each stack this run created, then each after; raise every failure."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps = list(extra or [])
    steps += [
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
