"""lambda-iot-describe-endpoint-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-iot-describe-endpoint-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    client = boto3.client("iot")
    try:
        resp = client.describe_endpoint(endpointType="iot:Data-ATS")
        return {"success": True, "endpointAddress": resp["endpointAddress"]}
    except ClientError as e:
        return {"success": False, "error_code": e.response["Error"]["Code"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A handler whose role lacks iot:DescribeEndpoint gets AccessDeniedException from iot.describe_endpoint,
    while a role with the permission returns the account's endpoint address."""
    iot = ctx.client("iot")

    # --- negative: role has only basic Lambda logging permissions, no IoT actions ---
    denied_role_arn = _create_lambda_role(ctx, None)
    denied_fn = _create_function(ctx, denied_role_arn, _HANDLER_CODE)

    payload = _invoke_json(ctx, denied_fn, {})
    assert payload["success"] is False, f"expected denial, got success payload {payload!r}"
    assert payload["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for missing iot:DescribeEndpoint permission, "
        f"got {payload['error_code']!r}"
    )

    # --- positive control: same handler, role WITH iot:DescribeEndpoint ---
    allowed_role_arn = _create_lambda_role(ctx, ["iot:DescribeEndpoint"])
    allowed_fn = _create_function(ctx, allowed_role_arn, _HANDLER_CODE)

    control_payload = _invoke_json(ctx, allowed_fn, {})
    assert control_payload["success"] is True, (
        f"positive control unexpectedly denied: {control_payload!r}"
    )

    expected = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    assert control_payload["endpointAddress"] == expected, (
        f"expected endpoint address {expected!r} at the destination, "
        f"got {control_payload['endpointAddress']!r} from the allowed function"
    )


def _make_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, iot_actions):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotlam-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    logs_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=logs_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=logs_policy_arn))

    if iot_actions:
        policy_name = "iot-inline-access"
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": iot_actions, "Resource": "*"}],
        }
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return role_arn


def _create_function(ctx, role_arn, handler_code):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-iotlam-fn-")
    zip_bytes = _make_zip(handler_code)
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    else:
        raise AssertionError(f"function creation never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke_json(ctx, name, payload=None):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload or {}).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


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
