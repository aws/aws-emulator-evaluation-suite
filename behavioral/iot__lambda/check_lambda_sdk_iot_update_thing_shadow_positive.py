"""lambda-sdk-iot-update-thing-shadow-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-iot-update-thing-shadow-positive"
GROUP = "sdk-call"
SERVICES = ["iot", "lambda"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A shadow a Lambda function writes with iot-data UpdateThingShadow is read back by an independent
    GetThingShadow call with reported temp 42."""
    iot = ctx.client("iot")
    thing_name = ctx.unique_name("sim2real-iotlam-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    thing_arn = f"arn:aws:iot:{ctx.region}:{_account_id(ctx)}:thing/{thing_name}"
    role_arn = _create_execution_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "iot:DescribeEndpoint", "Resource": "*"},
            {"Effect": "Allow", "Action": "iot:UpdateThingShadow", "Resource": thing_arn},
        ],
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER_SRC)

    marker = ctx.unique_name("marker-")
    state = {"reported": {"temp": 42, "marker": marker}}
    body = _invoke_until_delivered(ctx, fn_name, {"region": ctx.region, "thing_name": thing_name, "state": state})
    assert body == {"ok": True}, f"unexpected lambda response: {body!r}"

    iot_data = _iot_data_client(ctx)
    shadow = _poll_until(
        lambda: _get_shadow(iot_data, thing_name),
        lambda s: s is not None and s.get("state", {}).get("reported", {}).get("marker") == marker,
        timeout_s=60.0,
        interval_s=3.0,
        description="shadow document reflects the lambda-side UpdateThingShadow call",
    )
    assert shadow["state"]["reported"]["temp"] == 42, f"unexpected shadow reported state: {shadow!r}"


_ASSUME_ROLE_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}

_SIM2REAL_TAGS_DICT = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-iotlam"}
_SIM2REAL_TAGS_KV = [{"Key": k, "Value": v} for k, v in _SIM2REAL_TAGS_DICT.items()]

_HANDLER_SRC = (
    "import json\nimport boto3\n\n"
    "def handler(event, context):\n"
    "    region = event['region']\n"
    "    iot = boto3.client('iot', region_name=region)\n"
    "    ep = iot.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']\n"
    "    data = boto3.client('iot-data', region_name=region, endpoint_url='https://' + ep)\n"
    "    data.update_thing_shadow(thingName=event['thing_name'], payload=json.dumps({'state': event['state']}).encode('utf-8'))\n"
    "    return {'ok': True}\n"
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


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_execution_role(ctx, iot_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotlam-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ASSUME_ROLE_LAMBDA),
        Tags=_SIM2REAL_TAGS_KV,
    )["Role"]["Arn"]
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
                Tags=_SIM2REAL_TAGS_DICT,
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


def _invoke(ctx, fn_name: str, payload: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    return body, resp.get("FunctionError")


def _invoke_until_delivered(ctx, fn_name: str, payload: dict[str, Any], timeout_s: float = 60.0) -> dict[str, Any]:
    """Absorbs IAM role-propagation lag on the execution role's freshly
    attached policy by retrying the whole invocation a few times. A
    propagation-lag failure surfaces as an unhandled exception inside the
    handler (FunctionError), so it must be caught here rather than raised,
    or the retry below it would never run."""
    deadline = time.monotonic() + timeout_s
    last_body: dict[str, Any] = {}
    last_error: str | None = None
    while time.monotonic() < deadline:
        last_body, last_error = _invoke(ctx, fn_name, payload)
        if not last_error and last_body.get("ok"):
            return last_body
        time.sleep(4.0)
    if last_error:
        raise AssertionError(
            f"lambda invocation kept failing ({last_error}) for {timeout_s}s: {last_body!r}"
        )
    return last_body


def _iot_data_client(ctx):
    iot = ctx.client("iot")
    addr = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    url = ctx.endpoint_url(addr)
    return ctx.client("iot-data", endpoint_url=url)


def _get_shadow(iot_data, thing_name: str) -> dict[str, Any] | None:
    try:
        resp = iot_data.get_thing_shadow(thingName=thing_name)
        return json.loads(resp["payload"].read())
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


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
