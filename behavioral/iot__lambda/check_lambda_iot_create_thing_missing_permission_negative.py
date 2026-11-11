"""lambda-iot-create-thing-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-iot-create-thing-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    client = boto3.client("iot")
    try:
        client.create_thing(thingName=event["thingName"])
        return {"success": True}
    except ClientError as e:
        return {
            "success": False,
            "error_code": e.response["Error"]["Code"],
            "error_message": e.response["Error"]["Message"],
        }
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A handler whose role lacks iot:CreateThing gets AccessDeniedException with the exact message and the thing
    is never created, while a role with the permission creates it."""
    iot = ctx.client("iot")

    # --- negative: role has only basic Lambda logging permissions, no IoT actions ---
    denied_role_arn = _create_lambda_role(ctx, None)
    denied_fn = _create_function(ctx, denied_role_arn, _HANDLER_CODE)

    denied_thing_name = ctx.unique_name("sim2real-iotlam-thing-")
    payload = _invoke_json(ctx, denied_fn, {"thingName": denied_thing_name})
    assert payload["success"] is False, f"expected the unauthorized create_thing to be rejected, got {payload!r}"
    assert payload["error_code"] == "AccessDeniedException", f"unexpected error code: {payload!r}"
    expected = _create_thing_denied(ctx, denied_role_arn, denied_fn, denied_thing_name)
    assert payload["error_message"] == expected, (
        f"expected create_thing message {expected!r}, got {payload['error_message']!r}"
    )

    code, message = _error(lambda: iot.describe_thing(thingName=denied_thing_name))
    assert code == "ResourceNotFoundException", (
        f"denied create_thing must not have registered a thing, got describe_thing error {code!r}"
    )
    expected = _thing_not_found(ctx, denied_thing_name)
    assert message == expected, f"expected describe_thing message {expected!r}, got {message!r}"

    # --- positive control: same handler, role WITH iot:CreateThing ---
    allowed_role_arn = _create_lambda_role(ctx, ["iot:CreateThing"])
    allowed_fn = _create_function(ctx, allowed_role_arn, _HANDLER_CODE)

    allowed_thing_name = ctx.unique_name("sim2real-iotlam-thing-")
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=allowed_thing_name))
    control_payload = _invoke_until_delivered(ctx, allowed_fn, {"thingName": allowed_thing_name})
    assert control_payload["success"] is True, f"positive control lambda call failed: {control_payload!r}"

    desc = iot.describe_thing(thingName=allowed_thing_name)
    assert desc["thingName"] == allowed_thing_name, f"expected thingName {allowed_thing_name!r}, got {desc!r}"


def _error(fn):
    """The (code, message) a call is refused with; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _thing_not_found(ctx, thing_name: str) -> str:
    return f"Thing {ctx.account}:{thing_name} not found."


def _create_thing_denied(ctx, role_arn: str, function_name: str, thing_name: str) -> str:
    """IAM's refusal of iot:CreateThing for the function's execution-role session."""
    role_name = role_arn.rsplit("/", 1)[-1]
    return (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{function_name} is not "
        f"authorized to perform: iot:CreateThing on resource: "
        f"arn:aws:iot:{ctx.region}:{ctx.account}:thing/{thing_name} because no identity-based "
        f"policy allows the iot:CreateThing action"
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


def _invoke_until_delivered(ctx, name, payload, timeout_s: float = 60.0):
    """Absorbs IAM inline-policy propagation lag on the freshly attached iot:CreateThing allow."""
    deadline = time.monotonic() + timeout_s
    last = {}
    while time.monotonic() < deadline:
        last = _invoke_json(ctx, name, payload)
        if last.get("success"):
            return last
        time.sleep(4.0)
    return last


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
