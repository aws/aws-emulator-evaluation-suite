"""lambda-iot-get-thing-shadow-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-iot-get-thing-shadow-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]

_HANDLER_CODE = """
import boto3
import json
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    client = boto3.client("iot-data", endpoint_url=event["endpoint_url"])
    try:
        resp = client.get_thing_shadow(thingName=event["thingName"])
        doc = json.loads(resp["payload"].read())
        return {"success": True, "state": doc["state"]}
    except ClientError as e:
        return {
            "success": False,
            "error_code": e.response["Error"]["Code"],
            "error_message": e.response["Error"].get("Message", ""),
        }
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking iot:GetThingShadow gets a bare ForbiddenException from get_thing_shadow
    and no shadow document; a role WITH the permission retrieves the same shadow."""
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    endpoint_url = ctx.endpoint_url(endpoint)
    iot_data = ctx.client("iot-data", endpoint_url=endpoint_url)

    thing_name = ctx.unique_name("sim2real-iotlam-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    reported = {"battery": 87}
    iot_data.update_thing_shadow(
        thingName=thing_name, payload=json.dumps({"state": {"reported": reported}}).encode("utf-8")
    )
    ctx.on_cleanup(lambda: iot_data.delete_thing_shadow(thingName=thing_name))

    # --- negative: role has only basic Lambda logging permissions, no IoT actions ---
    denied_role_arn = _create_lambda_role(ctx, None)
    denied_fn = _create_function(ctx, denied_role_arn, _HANDLER_CODE)

    denied_payload = _invoke_json(
        ctx, denied_fn, {"endpoint_url": endpoint_url, "thingName": thing_name}
    )
    assert denied_payload["success"] is False, f"expected the unauthorized get_thing_shadow to fail: {denied_payload!r}"
    denied_code = denied_payload["error_code"]
    denied_msg = denied_payload.get("error_message", "")
    # The data plane refuses with a bare 403 that carries no message.
    assert (denied_code, denied_msg) == ("ForbiddenException", None), (
        f"unexpected error for missing IAM permission: code={denied_code!r} message={denied_msg!r}"
    )

    # independent read, bypassing the denied lambda entirely: the shadow document
    # itself is untouched by the denial, ruling out "there was nothing to get".
    control_doc = json.loads(iot_data.get_thing_shadow(thingName=thing_name)["payload"].read())
    assert control_doc["state"]["reported"] == reported, (
        f"shadow document must still hold the original reported state after the "
        f"denied call, independent of the lambda's own denial: {control_doc!r}"
    )

    # --- positive control: same handler, role WITH iot:GetThingShadow ---
    allowed_role_arn = _create_lambda_role(ctx, ["iot:GetThingShadow"])
    allowed_fn = _create_function(ctx, allowed_role_arn, _HANDLER_CODE)

    allowed_payload = _invoke_json(
        ctx, allowed_fn, {"endpoint_url": endpoint_url, "thingName": thing_name}
    )
    assert allowed_payload["success"] is True, f"positive control invocation failed: {allowed_payload!r}"
    assert allowed_payload["state"]["reported"] == reported, (
        f"positive control must retrieve the exact reported state written outside the "
        f"function: {allowed_payload!r}"
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
        Tags=[{"Key": "Name", "Value": role_name}],
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
                Tags={"Name": name},
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
