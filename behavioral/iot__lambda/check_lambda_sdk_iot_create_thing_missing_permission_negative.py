"""lambda-sdk-iot-create-thing-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-iot-create-thing-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A handler whose role lacks iot:CreateThing gets AccessDeniedException with the exact message and no thing
    exists; a sibling function with iot:CreateThing then creates it and describe_thing returns its ARN."""
    thing_name = ctx.unique_name("sim2real-iotlam-createneg-")

    denied_role_arn = _create_execution_role(ctx, [])
    allowed_role_arn = _create_execution_role(ctx, [{"Effect": "Allow", "Action": "iot:CreateThing", "Resource": "*"}])
    fn_denied = _create_function(ctx, denied_role_arn, _HANDLER_SRC)
    fn_allowed = _create_function(ctx, allowed_role_arn, _HANDLER_SRC)

    body_denied = _invoke_until_stable(ctx, fn_denied, {"region": ctx.region, "thing_name": thing_name})
    assert body_denied.get("ok") is False, f"expected the unauthorized create_thing to fail, got {body_denied!r}"
    assert body_denied["error"] == "AccessDeniedException", f"unexpected error code: {body_denied!r}"
    expected = _create_thing_denied(ctx, denied_role_arn, fn_denied, thing_name)
    assert body_denied["message"] == expected, (
        f"expected create_thing message {expected!r}, got {body_denied['message']!r}"
    )

    iot = ctx.client("iot")
    code, message = _error(lambda: iot.describe_thing(thingName=thing_name))
    assert code == "ResourceNotFoundException", (
        f"denied create_thing must not have registered any thing, got describe_thing error {code!r}"
    )
    expected = _thing_not_found(ctx, thing_name)
    assert message == expected, f"expected describe_thing message {expected!r}, got {message!r}"

    body_allowed = _invoke_until_delivered(ctx, fn_allowed, {"region": ctx.region, "thing_name": thing_name})
    assert body_allowed.get("ok") is True, f"positive control lambda call failed: {body_allowed!r}"
    lambda_thing_arn = body_allowed["thing_arn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    described = iot.describe_thing(thingName=thing_name)
    assert described["thingName"] == thing_name, f"expected thingName {thing_name!r}, got {described!r}"
    assert described["thingArn"] == lambda_thing_arn, (
        f"describe_thing arn {described['thingArn']!r} does not match the arn create_thing returned {lambda_thing_arn!r}"
    )


_ASSUME_ROLE_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}

_HANDLER_SRC = (
    "import boto3\n"
    "from botocore.exceptions import ClientError\n\n"
    "def handler(event, context):\n"
    "    try:\n"
    "        iot = boto3.client('iot', region_name=event['region'])\n"
    "        resp = iot.create_thing(thingName=event['thing_name'])\n"
    "        return {'ok': True, 'thing_arn': resp['thingArn']}\n"
    "    except ClientError as e:\n"
    "        return {'ok': False, 'error': e.response['Error']['Code'], 'message': e.response['Error']['Message']}\n"
)


def _error(fn):
    """The (code, message) a call is refused with; a call that succeeds fails the check."""
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_execution_role(ctx, iot_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotlam-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_ASSUME_ROLE_LAMBDA))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if iot_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="iot-access",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": iot_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="iot-access"))
    return role_arn


def _create_function(ctx, role_arn: str, handler_src: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-iotlam-fn-")
    zip_bytes = _zip_bytes(handler_src)

    def _try_create():
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            return lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    _poll_until(_try_create, lambda r: r is not None, timeout_s=60, interval_s=3.0, description=f"function {fn_name} create (role propagation)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {fn_name} Active",
    )
    return fn_name


def _invoke(ctx, fn_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed ({resp['FunctionError']}): {body!r}")
    return body


def _invoke_until_delivered(ctx, fn_name: str, payload: dict[str, Any], timeout_s: float = 60.0) -> dict[str, Any]:
    """Absorbs IAM role-propagation lag on a freshly attached allow policy."""
    deadline = time.monotonic() + timeout_s
    last_body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_body = _invoke(ctx, fn_name, payload)
        if last_body.get("ok"):
            return last_body
        time.sleep(4.0)
    return last_body


def _invoke_until_stable(ctx, fn_name: str, payload: dict[str, Any], attempts: int = 3) -> dict[str, Any]:
    """The denied role has no allow statement to propagate, so a handful of
    fixed retries is enough to rule out a purely transient error before we
    treat the rejection as the steady-state result."""
    last_body: dict[str, Any] = {}
    for _ in range(attempts):
        last_body = _invoke(ctx, fn_name, payload)
        if last_body.get("error") == "AccessDeniedException":
            return last_body
        time.sleep(2.0)
    return last_body


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
