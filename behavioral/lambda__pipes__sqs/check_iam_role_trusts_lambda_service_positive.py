"""iam-role-trusts-lambda-service-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trusts-lambda-service-positive"
GROUP = "arn-resolution"
SERVICES = ["lambda", "pipes", "sqs"]

_HANDLER_CODE = (
    "import json\n"
    "def handler(event, context):\n"
    "    return {'ok': True, 'input': event.get('marker')}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose trust policy names lambda.amazonaws.com as principal can actually be
    assumed by the Lambda service to run a real function invocation end to end."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lam-trust-")
    trust_doc = _trust_policy("lambda.amazonaws.com")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    function_name = ctx.unique_name("sim2real-lam-trust-fn-")
    zip_bytes = _lambda_zip_bytes(_HANDLER_CODE)

    create_resp = _create_function_with_retry(
        lam,
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=15,
        MemorySize=128,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    assert create_resp["Role"] == role_arn, (
        f"function's configured role should be {role_arn}, got {create_resp['Role']}"
    )

    _poll_until(
        lambda: lam.get_function(FunctionName=function_name)["Configuration"]["State"],
        lambda state: state in ("Active", "Failed"),
        timeout_s=60,
        interval_s=2,
    )
    final_state = lam.get_function(FunctionName=function_name)["Configuration"]["State"]
    assert final_state == "Active", f"function never became Active: {final_state}"

    invoke_resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps({"marker": "hello-marker-xyz"}).encode("utf-8"),
    )
    assert invoke_resp["StatusCode"] == 200, f"expected StatusCode 200, got {invoke_resp['StatusCode']}"
    assert "FunctionError" not in invoke_resp, (
        f"invocation reported a FunctionError: {invoke_resp.get('FunctionError')}"
    )
    payload = json.loads(invoke_resp["Payload"].read())
    assert payload == {"ok": True, "input": "hello-marker-xyz"}, (
        f"expected role-assumed invocation to echo the marker, got {payload}"
    )


def _trust_policy(service_principal: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _lambda_zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_function_with_retry(lam, *, attempts: int = 15, delay_s: float = 2.0, **kwargs):
    last_err = None
    for _ in range(attempts):
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_err = e
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
