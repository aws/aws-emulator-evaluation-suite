"""serverless-http-event-request-validator-rejects-missing-parameter."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "serverless-http-event-request-validator-rejects-missing-parameter"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_SLS_VERSION = "3.40.0"

_HANDLER = '''
import json


def main(event, context):
    print("INVOKED " + (event.get("headers") or {}).get("x-probe", ""))
    marker = (event.get("queryStringParameters") or {}).get("marker", "")
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"echo": marker}),
    }
'''

_TEMPLATE = """
service: {service}

provider:
  name: aws
  runtime: python3.12
  region: {region}
  endpointType: REGIONAL
  stackTags:
    sim2real:managed: "true"
  tags:
    sim2real:managed: "true"

functions:
  echo:
    handler: handler.main
    events:
      - http:
          method: get
          path: echo
          authorizer: aws_iam
          request:
            parameters:
              querystrings:
                marker: true
"""


def _run(args: list[str], *, cwd: str, env: dict, timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
    )


def _npm_install_serverless(workdir: str, env: dict) -> None:
    pkg = {"name": "sim2real-check", "version": "1.0.0", "private": True,
           "devDependencies": {"serverless": _SLS_VERSION}}
    Path(workdir, "package.json").write_text(json.dumps(pkg))
    # side-channel: the check pins and fetches Serverless Framework v3 from the public npm
    # registry at run time, exactly as a customer deploying with the tool would.
    r = subprocess.run(
        ["npm", "install", "--no-audit", "--no-fund"],
        cwd=workdir, env=env, capture_output=True, text=True, timeout=240,
    )
    assert r.returncode == 0, f"npm install serverless@{_SLS_VERSION} failed: {r.stderr[-2000:]}"


def _sls(args: list[str], *, workdir: str, env: dict, timeout: float) -> subprocess.CompletedProcess:
    return _run(
        ["npx", "--no-install", "serverless", *args],
        cwd=workdir, env=env, timeout=timeout,
    )


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                     budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
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
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


# Serverless Framework 3 calls AWS through the JavaScript SDK v2, which ctx.subprocess_env() points
# at an emulator's endpoint; this preload sends that SDK's S3 requests path-style, so every target is
# sent the same request shape.
_PATH_STYLE_PRELOAD = """
try {
  require(require.resolve("aws-sdk", { paths: [process.cwd()] })).config.update(
    { s3ForcePathStyle: true });
} catch (err) {
  if (err.code !== "MODULE_NOT_FOUND") throw err;
}
"""


def _env_for(ctx, workdir: str) -> dict:
    env = dict(ctx.subprocess_env())
    preload = os.path.join(workdir, "path-style-preload.js")
    with open(preload, "w") as fh:
        fh.write(_PATH_STYLE_PRELOAD)
    # Appended to the NODE_OPTIONS ctx.subprocess_env() sets, so its preload runs first.
    env["NODE_OPTIONS"] = f"{env.get('NODE_OPTIONS', '')} --require \"{preload}\"".lstrip()
    env["SLS_TELEMETRY_DISABLED"] = "1"
    env["CI"] = "1"
    env["NO_COLOR"] = "1"
    return env


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _physical_ids(cfn, stack: str, resource_type: str) -> list[str]:
    return sorted(r["PhysicalResourceId"]
                  for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
                  if r["ResourceType"] == resource_type)


def _logged(logs, log_group: str, needle: str) -> bool:
    """True once a line containing ``needle`` is in ``log_group``."""
    try:
        events = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{needle}"')["events"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return False
    return any(needle in e["message"] for e in events)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Serverless Framework http event's required query string makes API Gateway refuse a call
    without it with 400 and its exact message, never invoking the function; with it the call
    returns the handler's response.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html
    """
    require_tools("npm", "node")

    apigw = ctx.client("apigateway")
    logs = ctx.client("logs")
    lam = ctx.client("lambda")
    cfn = ctx.client("cloudformation")

    service = ctx.unique_name("sim2real")
    stage = "dev"
    stack_name = f"{service}-{stage}"
    function_name = f"{service}-{stage}-echo"

    workdir = tempfile.mkdtemp(prefix="sim2real-sls-httpneg-")
    # Registered first so LIFO removes the work dir only after `serverless remove` has run in it.
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    env = _env_for(ctx, workdir)
    _npm_install_serverless(workdir, env)
    Path(workdir, "handler.py").write_text(_HANDLER)
    Path(workdir, "serverless.yml").write_text(_TEMPLATE.format(service=service, region=ctx.region))

    def _stack_exists() -> bool:
        try:
            cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return False
            raise
        return True

    def _remove() -> None:
        if not _stack_exists():
            return
        r = _sls(["remove", "--stage", stage], workdir=workdir, env=env, timeout=600)
        assert r.returncode == 0, f"serverless remove failed: {r.stderr[-2000:]}\n{r.stdout[-2000:]}"

    ctx.on_cleanup(_remove)
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{function_name}"))

    deployed = _sls(["deploy", "--stage", stage], workdir=workdir, env=env, timeout=600)
    assert deployed.returncode == 0, (
        f"serverless deploy failed: {deployed.stderr[-2000:]}\n{deployed.stdout[-2000:]}"
    )

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    rest_api_ids = [
        r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::ApiGateway::RestApi"
    ]
    assert len(rest_api_ids) == 1, f"expected exactly one RestApi resource, found {rest_api_ids!r}"
    rest_api_id = rest_api_ids[0]
    role_names = _physical_ids(cfn, stack_name, "AWS::IAM::Role")
    buckets = _physical_ids(cfn, stack_name, "AWS::S3::Bucket")
    assert len(role_names) == 1 and len(buckets) == 1, (
        f"expected one execution role and one deployment bucket, got {role_names!r} {buckets!r}"
    )

    api_resources = apigw.get_resources(restApiId=rest_api_id)["items"]
    matches = [r["id"] for r in api_resources if r.get("pathPart") == "echo"]
    assert len(matches) == 1, f"expected exactly one 'echo' resource under {rest_api_id!r}, got {matches!r}"
    resource_id = matches[0]

    # Break exactly one thing: omit the required query string parameter.
    rejected_probe = ctx.unique_name("rejected-")
    rejected = apigw.test_invoke_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        pathWithQueryString="/echo",
        headers={"x-probe": rejected_probe},
    )
    assert rejected["status"] == 400, (
        f"TestInvokeMethod with no 'marker' param returned status {rejected['status']!r}, "
        "expected the RequestValidator to refuse it with 400"
    )
    body = json.loads(rejected["body"])
    assert body == {"message": "Missing required request parameters: [marker]"}, (
        f"400 body was {body!r}, expected APIGW's exact validation message naming 'marker'"
    )

    # Positive control, same method, same deployment: supplying the parameter reaches Lambda.
    marker = ctx.unique_name("m")
    accepted_probe = ctx.unique_name("accepted-")
    started = time.monotonic()
    accepted = apigw.test_invoke_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        pathWithQueryString=f"/echo?marker={marker}",
        headers={"x-probe": accepted_probe},
    )
    assert accepted["status"] == 200, (
        f"TestInvokeMethod with 'marker' present returned status {accepted['status']!r}, "
        "expected the positive control to reach the Lambda integration"
    )
    accepted_body = json.loads(accepted["body"])
    assert accepted_body == {"echo": marker}, (
        f"positive control body was {accepted_body!r}, expected the handler's echo of {marker!r}"
    )

    # Effect absent: the refused call never reached the function, held over a window derived
    # from how long the accepted call's invocation took to show in the function's log.
    log_group = f"/aws/lambda/{function_name}"
    deadline = started + 90.0
    while not _logged(logs, log_group, f"INVOKED {accepted_probe}"):
        assert time.monotonic() < deadline, (
            f"the accepted call's invocation never showed in {log_group!r} within 90s"
        )
        time.sleep(2.0)
    window_end = time.monotonic() + max(10.0, 3.0 * (time.monotonic() - started))
    while True:
        assert not _logged(logs, log_group, f"INVOKED {rejected_probe}"), (
            f"the function logged an invocation for the refused call {rejected_probe!r}"
        )
        if time.monotonic() >= window_end:
            break
        time.sleep(2.0)

    _remove()
    _reap_log_group(logs, log_group)

    gone = _error(lambda: cfn.describe_stacks(StackName=stack_name))
    assert gone == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"DescribeStacks on {stack_name!r} after serverless remove returned {gone!r}"
    )
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    gone = _error(lambda: lam.get_function(FunctionName=function_name))
    assert gone == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"GetFunction on {function_name!r} after serverless remove returned {gone!r}"
    )
    gone = _error(lambda: apigw.get_rest_api(restApiId=rest_api_id))
    assert gone == ("NotFoundException", f"Invalid API identifier specified {ctx.account}:{rest_api_id}"), (
        f"GetRestApi on {rest_api_id!r} after serverless remove returned {gone!r}"
    )
    gone = _error(lambda: ctx.client("iam").get_role(RoleName=role_names[0]))
    assert gone == ("NoSuchEntity", f"The role with name {role_names[0]} cannot be found."), (
        f"GetRole on the execution role after serverless remove returned {gone!r}"
    )
    gone = _error(lambda: ctx.client("s3").get_bucket_versioning(Bucket=buckets[0]))
    assert gone == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"GetBucketVersioning on the deployment bucket after serverless remove returned {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
