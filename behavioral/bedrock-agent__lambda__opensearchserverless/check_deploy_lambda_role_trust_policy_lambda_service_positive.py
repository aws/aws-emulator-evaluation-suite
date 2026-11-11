"""deploy-lambda-role-trust-policy-lambda-service-positive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-role-trust-policy-lambda-service-positive"
GROUP = "iam-trust"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The deployed Lambda execution role's AssumeRolePolicyDocument grants sts:AssumeRole to
    lambda.amazonaws.com, and that trust is what actually lets the Lambda service assume the
    role and run the function (verified by a real invocation, not just reading the document)."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-xsvc-lamrole-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(lambda: iam.detach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ))

    # 1. Assert the trust document exactly grants lambda.amazonaws.com sts:AssumeRole.
    fetched = iam.get_role(RoleName=role_name)["Role"]
    trust = fetched["AssumeRolePolicyDocument"]
    statement = trust["Statement"][0]
    assert statement["Effect"] == "Allow", f"expected Effect 'Allow', got {statement.get('Effect')!r}"
    assert statement["Action"] == "sts:AssumeRole", (
        f"expected Action 'sts:AssumeRole', got {statement.get('Action')!r}"
    )
    principal = statement["Principal"]
    service = principal["Service"] if isinstance(principal, dict) else principal
    assert service == "lambda.amazonaws.com", (
        f"expected trust Principal.Service 'lambda.amazonaws.com', got {service!r}"
    )

    # 2. Prove the trust is load-bearing: the Lambda service must assume this role at
    #    invoke time for the function to run at all.
    function_name = ctx.unique_name("sim2real-xsvc-fn-")
    code = _zip_from_source(
        "def handler(event, context):\n"
        "    return {'ok': True, 'from': context.invoked_function_arn}\n"
    )

    def _create():
        ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
        return lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role["Arn"],
            Handler="index.handler",
            Code={"ZipFile": code},
            Timeout=10,
            Tags={"sim2real-check": CHECK},
        )

    # IAM role propagation to Lambda is eventually consistent; retry create_function
    # on the specific transient error, not on any failure.
    _poll_until(
        lambda: _try(_create),
        lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
        description="create_function accepted the (eventually-consistent) role",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    state = _poll_until(
        lambda: lam.get_function(FunctionName=function_name)["Configuration"]["State"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=60,
        interval_s=2,
        description="function reached a terminal state (Active or Failed)",
    )
    assert state == "Active", f"expected function State 'Active', got {state!r}"

    result = lam.invoke(FunctionName=function_name, Payload=json.dumps({}).encode())
    assert result["StatusCode"] == 200, f"expected invoke StatusCode 200, got {result['StatusCode']!r}"
    assert "FunctionError" not in result, f"expected no FunctionError, got {result.get('FunctionError')!r}"
    payload = json.loads(result["Payload"].read())
    assert payload["ok"] is True, f"expected payload['ok'] is True, got {payload!r}"


def _try(fn):
    try:
        return fn()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"].get("Message", "")
        if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _zip_from_source(source: str) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


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
