"""ddb-stream-lambda-esm-missing-role-trust-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-stream-lambda-esm-missing-role-trust-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]
_UNTRUSTED_ROLE_MESSAGE = "The role defined for the function cannot be assumed by Lambda."


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction with a role that does not trust lambda.amazonaws.com fails with the exact
    error and creates no function, while the same function with a correctly trusted role is created
    and invokes with StatusCode 200 and no FunctionError."""
    lam = ctx.client("lambda")
    code = "def handler(event, context):\n    return {'ok': True}\n"

    # Broken trust: role only trusts ec2.amazonaws.com, never lambda.amazonaws.com.
    bad_role_arn, _ = _create_lambda_role(ctx, trust_service="ec2.amazonaws.com")
    bad_fn_name = ctx.unique_name("sim2real-fn-")

    def _attempt_create():
        ctx.on_cleanup(lambda _n=bad_fn_name: _delete_lambda_log_group(ctx, _n))
        lam.create_function(
            FunctionName=bad_fn_name,
            Runtime="python3.12",
            Role=bad_role_arn,
            Handler="index.handler",
            Code={"ZipFile": _zip_code(code)},
            Timeout=15,
            Publish=True,
            Tags={"sim2real": CHECK},
        )

    got = _error(_attempt_create)
    want = ("InvalidParameterValueException", _UNTRUSTED_ROLE_MESSAGE)
    assert got == want, f"CreateFunction with an untrusted role raised {got!r}, expected {want!r}"

    # Effect absent: the function was never created.
    got = _error(lambda: lam.get_function(FunctionName=bad_fn_name))
    want = (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn_name}",
    )
    assert got == want, (
        f"GetFunction for a function that was never created raised {got!r}, expected {want!r}"
    )

    # Positive control: a role that DOES trust lambda.amazonaws.com works end to end.
    good_role_arn, _ = _create_lambda_role(ctx)
    good_fn_name = _create_lambda_function(ctx, good_role_arn, code)
    resp = lam.invoke(FunctionName=good_fn_name, Payload=b"{}")
    assert resp["StatusCode"] == 200, f"expected StatusCode 200 for a healthy invoke, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"expected no FunctionError, got {resp.get('FunctionError')}"


def _error(fn):
    """(code, message) of a call real AWS refuses. RAISES if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused; it succeeded: {result!r}")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_lambda_role(ctx, extra_actions=None, trust_service="lambda.amazonaws.com"):
    """Create an execution role with basic-execution + DynamoDB-streams-read permissions
    (plus any extra_actions) and register teardown. Callers that use the role with
    Lambda retry past IAM propagation themselves (see `_create_lambda_function`)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=managed_arn))

    actions = [
        "dynamodb:GetRecords",
        "dynamodb:GetShardIterator",
        "dynamodb:DescribeStream",
        "dynamodb:ListStreams",
    ]
    if extra_actions:
        actions += extra_actions
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    }
    pol_name = f"{name}-inline"
    iam.put_role_policy(
        RoleName=name, PolicyName=pol_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pol_name))

    return role_arn, name


def _zip_code(code_str: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code_str)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn, code_str, env=None, timeout=30):
    """Create a Python Lambda function from inline code, retrying while the role
    propagates, and wait for the function to reach Active state."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_code(code_str)},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    last_exc = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_exc = e
            time.sleep(5)
    else:
        raise last_exc

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=90,
        interval_s=3.0,
        description=f"function {name} Active",
    )
    return name


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
