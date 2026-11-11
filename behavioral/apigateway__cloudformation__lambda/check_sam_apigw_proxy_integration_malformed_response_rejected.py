"""sam-apigw-proxy-integration-malformed-response-rejected."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "sam-apigw-proxy-integration-malformed-response-rejected"
GROUP = "deploy-sam"
SERVICES = ["apigateway", "cloudformation", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_apigw_proxy"
_TEMPLATE_FILE = "template.yaml"
_DEADLINE_S = 600.0


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A SAM Api proxy integration relays a function's proxy-shaped response verbatim, with the
    request's path, method and query string in the event, and rejects a non-proxy-shaped one.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    stack = ctx.unique_name("sim2real-apigwproxy-")
    bucket = ctx.unique_name("sim2real-apigwproxy-")
    good_fn = ctx.unique_name("sim2real-apigwproxy-good-")
    bad_fn = ctx.unique_name("sim2real-apigwproxy-bad-")
    work = _workdir(ctx, _PROJECT)

    _make_bucket(ctx, ctx.client("s3"), bucket)
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{good_fn}"))
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{bad_fn}"))
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack))
    _ok(_sam(ctx, work, _deploy_args(
        ctx, stack, bucket, "--no-fail-on-empty-changeset",
        "--parameter-overrides", f"GoodFunctionName={good_fn}", f"BadFunctionName={bad_fn}",
    )), "deploy")

    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", f"stack is {described['StackStatus']!r}"
    api_id = cfn.describe_stack_resource(StackName=stack, LogicalResourceId="Api")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    good_resource_id = _resource_id(apigw, api_id, "/good/{proxy+}")
    bad_resource_id = _resource_id(apigw, api_id, "/bad/{proxy+}")

    good = apigw.test_invoke_method(
        restApiId=api_id, resourceId=good_resource_id, httpMethod="ANY",
        pathWithQueryString="/good/widgets/42?color=blue", headers={"X-Test": "sim2real"},
    )
    assert good["status"] == 200, f"the proxy-shaped response must pass through; got {good!r}"
    good_body = json.loads(good["body"])
    assert good_body["path"] == "/good/widgets/42", f"unexpected event path {good_body!r}"
    assert good_body["httpMethod"] == "ANY", f"unexpected event httpMethod {good_body!r}"
    assert good_body["queryStringParameters"] == {"color": "blue"}, (
        f"unexpected event queryStringParameters {good_body!r}")

    bad = apigw.test_invoke_method(
        restApiId=api_id, resourceId=bad_resource_id, httpMethod="ANY",
        pathWithQueryString="/bad/widgets/42",
    )
    assert bad["status"] == 502, (
        f"a non-proxy-shaped Lambda response must be rejected with a 502; got {bad!r}")
    assert json.loads(bad["body"]) == {"message": "Internal server error"}, (
        f"unexpected malformed-proxy-response body {bad['body']!r}")
    assert bad["headers"].get("x-amzn-ErrorType") == "InternalServerErrorException", (
        f"unexpected malformed-proxy-response error type {bad['headers']!r}")

    # The control proves the rejection above is specific to the malformed shape, not to the
    # deploy or the wiring: the well-formed sibling integration still works after it.
    control = apigw.test_invoke_method(
        restApiId=api_id, resourceId=good_resource_id, httpMethod="ANY",
        pathWithQueryString="/good/still-ok",
    )
    assert control["status"] == 200, f"the good integration must still work; got {control!r}"

    roles = _stack_roles(cfn, described["StackId"])
    assert len(roles) == 2, f"expected the two functions' execution roles, got {roles!r}"
    _delete_stack(cfn, described["StackId"])
    good_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{good_fn}"
    code, message = _error(lambda: lam.get_function(FunctionName=good_fn))
    assert code == "ResourceNotFoundException", f"good function survived delete: {code!r}"
    assert message == f"Function not found: {good_arn}", f"unexpected message {message!r}"
    bad_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn}"
    code, message = _error(lambda: lam.get_function(FunctionName=bad_fn))
    assert code == "ResourceNotFoundException", f"bad function survived delete: {code!r}"
    assert message == f"Function not found: {bad_arn}", f"unexpected message {message!r}"
    code, message = _error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"rest api survived delete: {code!r}"
    assert message == f"Invalid API identifier specified {ctx.account}:{api_id}", (
        f"unexpected message {message!r}")
    _assert_roles_gone(ctx.client("iam"), roles)


def _resource_id(apigw, api_id: str, path: str) -> str:
    """The ``id`` of the resource at ``path`` (e.g. ``/good/{proxy+}``)."""
    for page in apigw.get_paginator("get_resources").paginate(restApiId=api_id):
        for item in page["items"]:
            if item["path"] == path:
                return item["id"]
    raise AssertionError(f"no resource at path {path!r} in api {api_id!r}")


def _error(fn):
    """(Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _sam(ctx, cwd: Path, args: list, *, timeout_s: float = 600.0):
    """Run the SAM CLI in ``cwd`` against the target, with telemetry off."""
    sam = shutil.which("sam")
    if sam is None:
        raise RequiredToolMissing(["sam"])
    ctx.verify_account_safety()
    return subprocess.run([sam, *args], cwd=cwd,
                          env={**ctx.subprocess_env(), "SAM_CLI_TELEMETRY": "0"},
                          capture_output=True, text=True, timeout=timeout_s)


def _ok(result, what: str) -> str:
    """stdout of a SAM CLI run that must exit 0."""
    assert result.returncode == 0, (
        f"`sam {what}` exited {result.returncode}: {(result.stdout + result.stderr)[-1500:]!r}")
    return result.stdout


def _deploy_args(ctx, stack: str, bucket: str, *extra: str) -> list:
    """``sam deploy`` of the template into the check's own bucket, never prompting."""
    return ["deploy", "--template-file", _TEMPLATE_FILE, "--stack-name", stack,
            "--s3-bucket", bucket, "--s3-prefix", stack, "--capabilities", "CAPABILITY_IAM",
            "--region", ctx.region, "--no-confirm-changeset", "--no-progressbar",
            "--tags", f"sim2real={CHECK}", *extra]


def _workdir(ctx, project: str) -> Path:
    """A scratch copy of the SAM project, so a build never writes into the source tree."""
    root = Path(tempfile.mkdtemp(prefix="sim2real-sam-"))
    ctx.on_cleanup(lambda: shutil.rmtree(root))
    work = root / "app"
    shutil.copytree(DEPLOYMENTS / project, work)
    return work


def _make_bucket(ctx, s3, name: str) -> None:
    """Create the deploy-artifact bucket with a teardown that empties and deletes it."""
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def empty_and_delete() -> None:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(empty_and_delete)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    """``probe()`` until ``done(result)``; returns the result and raises at the deadline."""
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
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by ``StackId`` and wait for ``DELETE_COMPLETE``; any other end raises."""
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
    """Delete the stack a CLI created under ``name``, if it exists, and wait for ``DELETE_COMPLETE``."""
    try:
        stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


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
