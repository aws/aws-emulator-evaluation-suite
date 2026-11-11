"""lambda-sdk-iot-list-things-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-iot-list-things-positive"
GROUP = "sdk-call"
SERVICES = ["iot", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """iot.list_things called inside a Lambda function sees a thing created outside the function, so the
    function reads the account's real registry."""
    iot = ctx.client("iot")
    thing_name = ctx.unique_name("sim2real-iotlam-list-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    role_arn = _create_execution_role(ctx, [{"Effect": "Allow", "Action": "iot:ListThings", "Resource": "*"}])
    fn_name = _create_function(ctx, role_arn, _HANDLER_SRC)

    body = _invoke_until_delivered(ctx, fn_name, {"region": ctx.region, "target": thing_name})
    assert body.get("ok") is True, f"unexpected lambda response: {body!r}"
    assert body["found"] is True, (
        f"lambda's list_things (scanned {body.get('scanned')} things) never saw thing {thing_name!r} "
        "created outside the function"
    )


_ASSUME_ROLE_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}

_HANDLER_SRC = (
    "import boto3\n\n"
    "def handler(event, context):\n"
    "    iot = boto3.client('iot', region_name=event['region'])\n"
    "    target = event['target']\n"
    "    token = None\n"
    "    scanned = 0\n"
    "    for _ in range(40):\n"
    "        kwargs = {'maxResults': 250}\n"
    "        if token:\n"
    "            kwargs['nextToken'] = token\n"
    "        resp = iot.list_things(**kwargs)\n"
    "        names = [t['thingName'] for t in resp.get('things', [])]\n"
    "        scanned += len(names)\n"
    "        if target in names:\n"
    "            return {'ok': True, 'found': True, 'scanned': scanned}\n"
    "        token = resp.get('nextToken')\n"
    "        if not token:\n"
    "            break\n"
    "    return {'ok': True, 'found': False, 'scanned': scanned}\n"
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
                Timeout=60,
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
    """Absorbs IAM role-propagation lag on the execution role's freshly
    attached policy, and the brief lag before a just-created thing is
    consistently visible to list_things, by retrying the invocation."""
    deadline = time.monotonic() + timeout_s
    last_body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_body = _invoke(ctx, fn_name, payload)
        if last_body.get("ok") and last_body.get("found"):
            return last_body
        time.sleep(4.0)
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
