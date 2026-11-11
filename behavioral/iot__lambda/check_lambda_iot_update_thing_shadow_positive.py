"""lambda-iot-update-thing-shadow-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-iot-update-thing-shadow-positive"
GROUP = "data-plane-sdk"
SERVICES = ["iot", "lambda"]

_HANDLER_CODE = """
import boto3
import json

def lambda_handler(event, context):
    client = boto3.client("iot-data", endpoint_url=event["endpoint_url"])
    resp = client.update_thing_shadow(
        thingName=event["thingName"],
        payload=json.dumps({"state": {"reported": event["reported"]}}).encode("utf-8"),
    )
    doc = json.loads(resp["payload"].read())
    return {"state": doc["state"], "version": doc["version"]}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose execution role grants iot:UpdateThingShadow writes a new
    shadow document from inside its handler, and the new state it wrote is retrievable via
    get_thing_shadow called directly against the IoT data plane (outside the function)."""
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    endpoint_url = ctx.endpoint_url(endpoint)
    iot_data = ctx.client("iot-data", endpoint_url=endpoint_url)

    thing_name = ctx.unique_name("sim2real-iotlam-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    ctx.on_cleanup(lambda: iot_data.delete_thing_shadow(thingName=thing_name))

    role_arn = _create_lambda_role(ctx, ["iot:UpdateThingShadow"])
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE)

    reported = {"fanSpeed": 3, "mode": "cool"}
    payload = _invoke_json(
        ctx, fn_name, {"endpoint_url": endpoint_url, "thingName": thing_name, "reported": reported}
    )
    assert payload["state"]["reported"] == reported, (
        f"lambda-side UpdateThingShadow response reported state mismatch: {payload!r}"
    )
    assert payload["version"] == 1, f"expected first-write shadow version 1, got {payload!r}"

    doc = json.loads(iot_data.get_thing_shadow(thingName=thing_name)["payload"].read())
    assert doc["state"]["reported"] == reported, (
        f"independent GetThingShadow reported state does not match what the lambda wrote: {doc!r}"
    )
    assert doc["version"] == 1, f"independent GetThingShadow expected version 1, got {doc!r}"


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
