"""sam-httpapi-aws-iam-route-unsigned-forbidden-signed-served."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "sam-httpapi-aws-iam-route-unsigned-forbidden-signed-served"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_httpapi_iam"
_TEMPLATE_FILE = ".aws-sam/build/template.yaml"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A SAM HttpApi route with `Auth.Authorizer: AWS_IAM` refuses an unsigned request with 403
    {"message":"Forbidden"} and serves a SigV4-signed one with the function's own response,
    naming the signing caller in `requestContext.authorizer.iam`.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-httpapi.html#sam-function-httpapi-auth
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = ctx.unique_name("sim2real-sam-hiam-")
    stack = ctx.unique_name("sim2real-sam-hiam-")
    work = _workdir(ctx, _PROJECT)

    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack))
    _ok(_sam(ctx, work, ["build", "--region", ctx.region]), "build")
    _ok(_sam(ctx, work, _deploy_args(ctx, stack, {"FunctionName": fn})), "deploy")

    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    outputs = _outputs(cfn, stack_id)
    base_url = outputs["Endpoint"]
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    got_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]
    assert got_arn == fn_arn, f"the deployed function describes as {got_arn!r}, expected {fn_arn!r}"
    agw = ctx.client("apigatewayv2")
    api_id = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Api")[
        "StackResourceDetail"]["PhysicalResourceId"]
    routes = {r["RouteKey"]: r["AuthorizationType"] for r in agw.get_routes(ApiId=api_id)["Items"]}
    assert routes == {"GET /secure": "AWS_IAM"}, (
        f"GetRoutes must read back the one AWS_IAM route SAM declared; got {routes!r}"
    )

    access_key = ctx.client("lambda")._request_signer._credentials.get_frozen_credentials().access_key
    url = f"{base_url}/secure"

    # The route itself (not the integration) needs to finish propagating before it answers at all.
    unsigned = _poll(
        lambda: _get(ctx, url), lambda r: r.status_code != 404,
        timeout_s=60.0, interval_s=2.0, what="the route to stop 404ing",
    )
    assert unsigned.status_code == 403, (
        f"an unsigned request to the AWS_IAM route must be refused 403, got {unsigned.status_code}: "
        f"{unsigned.text[:200]!r}"
    )
    assert json.loads(unsigned.text) == {"message": "Forbidden"}, (
        f'the refusal must be the HttpApi authorizer\'s {{"message":"Forbidden"}} envelope, got '
        f"{unsigned.text[:200]!r}"
    )

    signed = _poll(
        lambda: _get(ctx, url, sign=True), lambda r: r.status_code == 200,
        timeout_s=120.0, interval_s=2.0, what="the signed GET being served",
    )
    body = json.loads(signed.text)
    assert body["accountId"] == ctx.account, (
        f"authorizer.iam.accountId must be the signing caller's account; got {body!r}"
    )
    assert body["accessKey"] == access_key, (
        f"authorizer.iam.accessKey must be the access key the request was signed with; got {body!r}"
    )
    assert body["userArn"].split(":")[4] == ctx.account, (
        f"authorizer.iam.userArn must be an ARN in the caller's account; got {body!r}"
    )

    again = _get(ctx, url)
    assert (again.status_code, json.loads(again.text)) == (403, {"message": "Forbidden"}), (
        f"an unsigned request must still be refused after a signed one, got "
        f"{(again.status_code, again.text[:200])!r}"
    )

    roles = _stack_roles(cfn, stack_id)
    assert len(roles) == 1, f"expected the function's execution role, got {roles!r}"
    _delete_stack_named(cfn, stack)

    gone_api = _absent(lambda: agw.get_api(ApiId=api_id))
    assert gone_api == ("NotFoundException", f"Invalid API identifier specified {ctx.account}:{api_id}"), (
        f"GetApi after the in-band delete: {gone_api!r}"
    )
    _assert_roles_gone(ctx.client("iam"), roles)
    gone_fn = _absent(lambda: lam.get_function(FunctionName=fn))
    assert gone_fn == (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}",
    ), f"GetFunction after the in-band delete must name the function's own ARN; got {gone_fn!r}"


def _sign(ctx, method: str, url: str, headers: dict, data) -> dict:
    """SigV4 headers for a request to ``url``, signed for execute-api with the caller's own creds."""
    frozen = ctx.client("lambda")._request_signer._credentials.get_frozen_credentials()
    req = AWSRequest(method=method, url=url, data=data, headers=dict(headers))
    SigV4Auth(frozen, "execute-api", ctx.region).add_auth(req)
    return dict(req.headers.items())


def _get(ctx, url: str, *, sign: bool = False) -> requests.Response:
    target, route = ctx.endpoint_route(url)
    headers = dict(route)
    if sign:
        headers = {**headers, **_sign(ctx, "GET", target, headers, None)}
    return requests.get(target, headers=headers, verify=ctx.http_verify, timeout=30)


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])}


def _absent(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _delete_stack_named(cfn, name: str) -> None:
    """Delete the stack `sam deploy` created under `name`, if it exists, and wait for DELETE_COMPLETE."""
    try:
        stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


def _sam(ctx, cwd: Path, args: list, *, timeout_s: float = 600.0):
    """Run the SAM CLI in ``cwd`` against the target, with telemetry off."""
    sam = shutil.which("sam")
    if sam is None:
        raise RequiredToolMissing(["sam"])
    ctx.verify_account_safety()
    return subprocess.run(
        [sam, *args], cwd=cwd, env={**ctx.subprocess_env(), "SAM_CLI_TELEMETRY": "0"},
        capture_output=True, text=True, timeout=timeout_s,
    )


def _ok(result, what: str) -> None:
    """Assert a SAM CLI run exited 0."""
    assert result.returncode == 0, (
        f"`sam {what}` exited {result.returncode}: {(result.stdout + result.stderr)[-1500:]!r}"
    )


def _deploy_args(ctx, stack: str, params: dict) -> list:
    """`sam deploy` of the built template; InlineCode needs no packaging bucket."""
    overrides = [f"{k}={v}" for k, v in params.items()]
    return [
        "deploy", "--template-file", _TEMPLATE_FILE, "--stack-name", stack,
        "--capabilities", *_CAPS, "--region", ctx.region,
        "--no-confirm-changeset", "--no-progressbar",
        "--parameter-overrides", *overrides,
        "--tags", f"sim2real={CHECK}",
    ]


def _workdir(ctx, project: str) -> Path:
    """A scratch copy of the SAM project, so a build never writes into the source tree."""
    root = Path(tempfile.mkdtemp(prefix="sim2real-sam-"))
    ctx.on_cleanup(lambda: shutil.rmtree(root))
    work = root / "app"
    shutil.copytree(DEPLOYMENTS / project, work)
    return work


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 2.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads, ``interval_s`` apart, find it
    absent; a late log flush that re-creates the group is deleted again."""
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
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


def _stack_roles(cfn, stack: str) -> list[str]:
    """Names of every AWS::IAM::Role the stack created, read before its delete."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    return sorted(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::IAM::Role")


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """Each role answers NoSuchEntity with IAM's exact message."""
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
                f"GetRole({role!r}) after the stack delete: {got!r}"
            )
            continue
        raise AssertionError(f"role {role!r} survived the stack delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
