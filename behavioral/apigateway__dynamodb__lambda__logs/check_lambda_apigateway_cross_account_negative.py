"""lambda-apigateway-cross-account-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-apigateway-cross-account-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

# The Lambda handler signs its own outbound HTTPS request to the API Gateway
# execute-api endpoint with the function's own execution-role credentials (SigV4),
# then reports the raw HTTP status code/body it got back. This lets us observe how
# API Gateway's resource policy evaluates the caller identity end to end.
INVOKE_CODE = """
import json
import os
import urllib.request
import urllib.error

import botocore.session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

def handler(event, context):
    url = event["url"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    session = botocore.session.get_session()
    credentials = session.get_credentials().get_frozen_credentials()
    # Do NOT hand-set the Host header before signing: AWSRequest.prepare()
    # derives it from the URL, and letting urllib set its own Host on top of a
    # manually-signed one produces a Host mismatch that API Gateway treats as an
    # unverifiable (anonymous) signature rather than a signature error -- which
    # silently defeats this test's account-scoping assertion for BOTH the open
    # and restricted APIs. Sign the prepared request instead so the exact bytes
    # that get sent are the exact bytes that were signed.
    request = AWSRequest(method="GET", url=url)
    SigV4Auth(credentials, "execute-api", region).add_auth(request)
    prepared = request.prepare()
    req = urllib.request.Request(prepared.url, headers=dict(prepared.headers), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"statusCode": resp.status, "body": resp.read().decode()}
    except urllib.error.HTTPError as e:
        return {"statusCode": e.code, "body": e.read().decode()}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A REST API resource policy allowing execute-api:Invoke only for another account denies a
    SigV4-signed call from a Lambda in the caller's account with 403 and no backend body, while a
    sibling API scoped to the caller's own account returns 200 and the mock body."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_account = "111111111111" if account_id != "111111111111" else "222222222222"

    open_api_id, _ = _create_signed_api(ctx, _account_scoped_policy(account_id))
    restricted_api_id, _ = _create_signed_api(ctx, _account_scoped_policy(bogus_account))

    role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": "*"}]
    )
    fn_name = _create_lambda_function(ctx, role_arn, INVOKE_CODE)

    open_url = f"{ctx.api_url(open_api_id, 'prod')}/"
    restricted_url = f"{ctx.api_url(restricted_api_id, 'prod')}/"

    open_result = _poll_invoke(ctx, fn_name, {"url": open_url}, expect_status=200)
    assert open_result["statusCode"] == 200, open_result
    assert '"message": "ok"' in open_result["body"], open_result

    restricted_result = _poll_invoke(ctx, fn_name, {"url": restricted_url}, expect_status=403)
    assert restricted_result["statusCode"] == 403, restricted_result
    # Match the mock's exact success payload, not a loose "ok" substring: the
    # resource-policy denial error text itself contains "...execute-api:Invoke..."
    # which contains "ok" as a substring ("inv-OK-e"), so a naive `"ok" in body`
    # check would false-fail on a correctly-denied response.
    assert '"message": "ok"' not in restricted_result["body"], "mock backend must not have been reached"
    role_name = role_arn.rsplit("/", 1)[-1]
    want_denial = {
        "Message": (
            f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{fn_name} is not "
            f"authorized to perform: execute-api:Invoke on resource: arn:aws:execute-api:"
            f"{ctx.region}:********{account_id[-4:]}:{restricted_api_id}/prod/GET/ with an "
            f"explicit deny in a resource-based policy"
        )
    }
    assert json.loads(restricted_result["body"]) == want_denial, (
        f"expected the resource-policy denial {want_denial!r}, got {restricted_result['body']!r}"
    )


# ===== helpers (self-contained) =====
_XSVC_TAG_KEY = "sim2real:managed"


def _iam_tags() -> list[dict[str, str]]:
    return [{"Key": _XSVC_TAG_KEY, "Value": "true"}]


def _lambda_tags() -> dict[str, str]:
    return {_XSVC_TAG_KEY: "true"}


def _delete_log_group_persistently(ctx, name: str, *, attempts: int = 3, delay: float = 20.0) -> None:
    """Delete a log group, and RE-DELETE it if an async writer recreates it.

    The Lambda service holds
    logs:CreateLogGroup, and a flush that lands AFTER this teardown ran recreates the
    group -- a single delete_log_group therefore leaves a leaked group behind. Deleting
    until the group stays gone is what makes this teardown actually undo the create.
    """
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    for _ in range(attempts):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(delay)
        alive = [
            g["logGroupName"]
            for g in logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
            if g["logGroupName"] == name
        ]
        if not alive:
            return
    raise AssertionError(f"LEAK: log group {name} was recreated by an async writer after {attempts} deletes")


def _account_scoped_policy(allowed_account: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "execute-api:Invoke",
                "Resource": "execute-api:/*",
                "Condition": {"StringNotEquals": {"aws:PrincipalAccount": allowed_account}},
            },
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "execute-api:Invoke",
                "Resource": "execute-api:/*",
            },
        ],
    }


def _create_signed_api(ctx, policy_doc: dict[str, Any]) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-xacct-api-")
    api = apigw.create_rest_api(name=name, policy=json.dumps(policy_doc))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    # AWS_IAM (not NONE) is required here: API Gateway only extracts a
    # SigV4-verified caller identity -- the aws:PrincipalAccount the resource
    # policy's condition checks -- when the method itself demands IAM auth. With
    # authorizationType=NONE, API Gateway never attempts signature verification,
    # so even a correctly SigV4-signed request is evaluated as principal
    # "anonymous" against the resource policy, and the explicit Deny always wins
    # regardless of which account actually signed the request.
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="AWS_IAM")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "ok"}'},
    )
    apigw.create_deployment(restApiId=api_id, stageName="prod")
    return api_id, root_id


def _zip_code(filename: str, code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_iam_tags()
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_arn))
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-lam-pol-")
        doc = {"Version": "2012-10-17", "Statement": policy_statements}
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lam-fn-")
    zip_bytes = _zip_code("index.py", code)
    last_err = None
    for _ in range(15):
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags=_lambda_tags(),
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
            continue
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    # The function auto-creates /aws/lambda/<name> on first invoke; that log group
    # survives function deletion, so it would
    # leak on every run of this check (which invokes the function twice, guaranteeing
    # the group is created).
    ctx.on_cleanup(lambda: _delete_log_group_persistently(ctx, f"/aws/lambda/{name}"))
    _wait_for_active(ctx, name)
    return name


def _wait_for_active(ctx, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda {name} never became Active")


def _invoke(ctx, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invoke error: {body}")
    return body


def _poll_invoke(
    ctx, name: str, payload: dict[str, Any], expect_status: int, timeout_s: float = 180.0, interval_s: float = 10.0
) -> dict[str, Any]:
    # Resource policy attachment/deployment propagation on API Gateway is not
    # instantaneous, so poll for the expected status rather than asserting on the
    # first attempt.
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = _invoke(ctx, name, payload)
        if last.get("statusCode") == expect_status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"never observed statusCode={expect_status}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
