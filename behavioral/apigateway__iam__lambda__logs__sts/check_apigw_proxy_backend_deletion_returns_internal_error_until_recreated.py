"""apigw-proxy-backend-deletion-returns-internal-error-until-recreated."""
from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-proxy-backend-deletion-returns-internal-error-until-recreated"
GROUP = "lambda-proxy-backend-lifecycle"
SERVICES = ["apigateway", "iam", "lambda", "logs", "sts"]

_THROTTLE = ("TooManyRequestsException",)
_HANDLER = textwrap.dedent(
    """
    import json


    def lambda_handler(event, context):
        return {{
            "statusCode": 200,
            "headers": {{"Content-Type": "application/json"}},
            "body": json.dumps({{"marker": "{marker}"}}),
        }}
    """
)


def _error(fn):
    """(Error.Code, Error.Message) the call raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _retry_throttle(fn, **kwargs):
    for attempt in range(8):
        try:
            return fn(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE or attempt == 7:
                raise
            time.sleep(min(5.0, 0.5 * (2**attempt)))
    raise AssertionError("unreachable")


def _get(url, timeout_s=15.0):
    """One GET against url: (status, lowercased headers, body text)."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - fixed https
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read().decode()
    except OSError as exc:
        return None, {}, repr(exc)


def _poll_until(url, accept, what, *, budget_s=180.0, interval_s=3.0):
    """Poll GET url until accept(status, headers, body) holds; raise the last response past budget_s."""
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        last = _get(url)
        if accept(*last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {what}; last response was {last!r}")
        time.sleep(interval_s)


def _body_marker(body):
    try:
        return json.loads(body).get("marker")
    except ValueError:
        return None


def _zip_with(marker):
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _HANDLER.format(marker=marker))
    return buf.getvalue()


def _delete_role(iam, role_name):
    for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    iam.delete_role(RoleName=role_name)


def _delete_function_if_present(lam, fn_name):
    try:
        lam.delete_function(FunctionName=fn_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _reap_log_group(logs, group_name, *, reads=3, interval_s=5.0, budget_s=180.0):
    """Delete group_name until `reads` consecutive reads find it absent, tolerating a flush
    that recreates it right after a delete."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        found = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"]
        if any(g["logGroupName"] == group_name for g in found):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=group_name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {group_name} kept reappearing after delete")
            time.sleep(interval_s)


def _delete_rest_api(ag, api_id):
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code not in _THROTTLE or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _invoke_policy(ctx):
    """A resource policy admitting execute-api:Invoke only from the runner's own addresses."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "execute-api:Invoke",
                    "Resource": "execute-api:/*",
                    "Condition": {"IpAddress": {"aws:SourceIp": ctx.ingress_cidrs()}},
                }
            ],
        }
    )


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-apigw-pbd-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    return role_arn


def _create_function(ctx, role_arn, fn_name, marker):
    """Create fn_name with marker baked into its response body, retrying the brief windows
    where a fresh role is not yet assumable or a just-deleted name is not yet reusable."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            created = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": _zip_with(marker)},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(3.0)
    lam.get_waiter("function_active_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 45}
    )
    return created["FunctionArn"]


def _grant_invoke(ctx, fn_name, source_arn):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A deployed AWS_PROXY stage answers 500 InternalServerErrorException once its backend
    function is deleted, GetFunction then raises ResourceNotFoundException naming it, and
    recreating the function under the same name and re-granting invoke serves only its own marker.
    """
    ag = ctx.client("apigateway")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    role_arn = _create_execution_role(ctx)

    fn_name = ctx.unique_name("sim2real-apigw-pbd-fn-")
    first_marker = ctx.unique_name("sim2real-apigw-pbd-m1-")
    second_marker = ctx.unique_name("sim2real-apigw-pbd-m2-")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:{fn_name}"

    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
    _create_function(ctx, role_arn, fn_name, first_marker)
    ctx.on_cleanup(lambda: _delete_function_if_present(lam, fn_name))

    api_id = _retry_throttle(
        ag.create_rest_api,
        name=ctx.unique_name("sim2real-apigw-pbd-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        policy=_invoke_policy(ctx),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = _retry_throttle(
        ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="call"
    )["id"]
    _retry_throttle(
        ag.put_method, restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="NONE",
    )
    integration_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    )
    _retry_throttle(
        ag.put_integration, restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        type="AWS_PROXY", integrationHttpMethod="POST", uri=integration_uri,
    )

    stage = "s" + ctx.unique_name("")
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/{stage}/GET/call"
    _grant_invoke(ctx, fn_name, source_arn)

    deployment_id = _retry_throttle(ag.create_deployment, restApiId=api_id)["id"]
    _retry_throttle(
        ag.create_stage, restApiId=api_id, stageName=stage, deploymentId=deployment_id
    )
    ctx.on_cleanup(lambda: _retry_throttle(ag.delete_stage, restApiId=api_id, stageName=stage))

    url = f"{ctx.rest_api_url(api_id, stage)}/call"

    got = lam.get_function(FunctionName=fn_name)
    assert got["Configuration"]["FunctionName"] == fn_name, (
        f"GetFunction before deletion returned {got['Configuration']['FunctionName']!r}, "
        f"expected {fn_name!r}"
    )

    _, _, body = _poll_until(
        url, lambda s, h, b: s == 200, "the fresh stage to serve the first function",
        budget_s=240.0,
    )
    assert json.loads(body) == {"marker": first_marker}, (
        f"first invoke returned {body!r}, expected marker {first_marker!r}"
    )

    lam.delete_function(FunctionName=fn_name)

    _, headers, body = _poll_until(
        url, lambda s, h, b: s == 500, "the stage to answer 500 once its backend is deleted",
        budget_s=120.0,
    )
    assert headers.get("x-amzn-errortype") == "InternalServerErrorException", (
        f"deleted-backend response carried x-amzn-ErrorType {headers.get('x-amzn-errortype')!r}"
    )
    assert json.loads(body) == {"message": "Internal server error"}, (
        f"deleted-backend response body was {body!r}, expected the internal-error message"
    )

    code, message = _error(lambda: lam.get_function(FunctionName=fn_name))
    assert code == "ResourceNotFoundException", (
        f"GetFunction on the deleted function gave {code}: {message!r}"
    )
    assert message == f"Function not found: {fn_arn}", (
        f"GetFunction message was {message!r}, expected it to name {fn_arn!r}"
    )

    _create_function(ctx, role_arn, fn_name, second_marker)
    _grant_invoke(ctx, fn_name, source_arn)

    _, _, body = _poll_until(
        url,
        lambda s, h, b: s == 200 and _body_marker(b) == second_marker,
        "the stage to serve the recreated function's own marker",
        budget_s=150.0,
    )
    assert json.loads(body) == {"marker": second_marker}, (
        f"after recreation the stage served {body!r}, expected only the new marker {second_marker!r}"
    )
    assert first_marker not in body, (
        f"the recreated function's response still carries the old marker: {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
