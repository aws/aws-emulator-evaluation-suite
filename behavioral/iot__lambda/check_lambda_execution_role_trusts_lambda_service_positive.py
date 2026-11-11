"""lambda-execution-role-trusts-lambda-service-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-execution-role-trusts-lambda-service-positive"
GROUP = "iam-trust"
SERVICES = ["iot", "lambda"]

_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose AssumeRolePolicyDocument trusts lambda.amazonaws.com lets CreateFunction
    succeed, and the resulting function can actually assume that role at invoke time to make
    an AWS SDK call against iot (the iam_trust + sdk_call integration edges combined)."""
    role_arn, role_name = _create_role(
        ctx,
        ["lambda.amazonaws.com"],
        inline_policies={
            "iot-describe-endpoint": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "iot:DescribeEndpoint", "Resource": "*"}
                ],
            }
        },
        managed_policy_arns=[_BASIC_EXEC_POLICY],
    )
    fn_name = ctx.unique_name("sim2real-iotlambda-fn-")
    _create_function_with_retry(ctx, fn_name, role_arn, _lambda_zip_describe_iot_endpoint())

    lam = ctx.client("lambda")
    _wait_for_function_active(ctx, fn_name)
    resp = _invoke_with_retry(lam, fn_name)
    payload = json.loads(resp["Payload"].read())

    assert resp.get("FunctionError") is None, f"invocation errored: {payload}"

    expected_endpoint = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")[
        "endpointAddress"
    ]
    actual_endpoint = payload.get("endpointAddress")
    assert actual_endpoint == expected_endpoint, (
        f"lambda-resolved endpoint {actual_endpoint!r} != independently-resolved endpoint "
        f"{expected_endpoint!r}"
    )


def _lambda_zip_describe_iot_endpoint() -> bytes:
    src = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    iot = boto3.client('iot')\n"
        "    resp = iot.describe_endpoint(endpointType='iot:Data-ATS')\n"
        "    return {'endpointAddress': resp['endpointAddress']}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_role(ctx, principals, inline_policies=None, managed_policy_arns=None):
    iam = ctx.client("iam")
    principal = principals[0] if len(principals) == 1 else principals
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    name = ctx.unique_name("sim2real-iotlambda-role-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_name, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    for arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
    role = iam.get_role(RoleName=name)["Role"]
    return role["Arn"], name


def _delete_role(ctx, role_name) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_for_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        last_state = cfg.get("State")
        if last_state == "Active":
            return cfg
        if last_state == "Failed":
            raise RuntimeError(f"function {name} entered Failed state: {cfg}")
        time.sleep(2)
    raise TimeoutError(f"function {name} did not become Active (last state={last_state})")


def _invoke_with_retry(lam, fn_name, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceConflictException":
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _create_function_with_retry(ctx, name, role_arn, zip_bytes, env=None, timeout_s=90.0):
    lam = ctx.client("lambda")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=30,
        Tags={"sim2real:managed": "true"},
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            return resp
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            last_err = e
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                time.sleep(3)
                continue
            raise
    raise last_err


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
