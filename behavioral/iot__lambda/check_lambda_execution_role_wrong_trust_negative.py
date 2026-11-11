"""lambda-execution-role-wrong-trust-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-execution-role-wrong-trust-negative"
GROUP = "iam-trust"
SERVICES = ["iot", "lambda"]

_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_UNASSUMABLE_ROLE = "The role defined for the function cannot be assumed by Lambda."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role trusting only s3.amazonaws.com is refused by CreateFunction and UpdateFunctionConfiguration with
    InvalidParameterValueException and the exact message; a lambda-trusted role works and stays configured."""
    lam = ctx.client("lambda")

    bad_role_arn, _bad_role_name = _create_role(ctx, ["s3.amazonaws.com"])
    bad_fn_name = ctx.unique_name("sim2real-iotlambda-fn-")

    code, message = _error(
        lambda: lam.create_function(
            FunctionName=bad_fn_name,
            Runtime="python3.12",
            Role=bad_role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": _lambda_zip_describe_iot_endpoint()},
            Timeout=30,
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a role trusting only "
        f"s3.amazonaws.com, got {code!r}"
    )
    assert message == _UNASSUMABLE_ROLE, (
        f"expected CreateFunction message {_UNASSUMABLE_ROLE!r}, got {message!r}"
    )
    get_code, get_message = _error(lambda: lam.get_function(FunctionName=bad_fn_name))
    assert get_code == "ResourceNotFoundException", (
        f"expected no function to have been created for the rejected CreateFunction call, "
        f"but get_function returned {get_code!r}"
    )
    expected = _function_not_found(ctx, bad_fn_name)
    assert get_message == expected, f"expected get_function message {expected!r}, got {get_message!r}"

    # Positive control: a correctly-trusted role creates and keeps its function successfully.
    good_role_arn, _good_role_name = _create_role(
        ctx, ["lambda.amazonaws.com"], managed_policy_arns=[_BASIC_EXEC_POLICY]
    )
    good_fn_name = ctx.unique_name("sim2real-iotlambda-fn-")
    _create_function_with_retry(
        ctx, good_fn_name, good_role_arn, _lambda_zip_describe_iot_endpoint()
    )
    # UpdateFunctionConfiguration (below) fails with ResourceConflictException while the
    # function is still Pending right after creation, so wait for Active first.
    _wait_for_function_active(ctx, good_fn_name)
    good_config = lam.get_function_configuration(FunctionName=good_fn_name)
    assert good_config["Role"] == good_role_arn, (
        f"expected the positive-control function's role to be {good_role_arn!r}, "
        f"got {good_config['Role']!r}"
    )

    # The same wrongly-trusted role is also rejected by UpdateFunctionConfiguration, and the
    # function's role is left untouched (the effect did not persist).
    update_code, update_message = _error(
        lambda: lam.update_function_configuration(FunctionName=good_fn_name, Role=bad_role_arn)
    )
    assert update_code == "InvalidParameterValueException", (
        f"expected UpdateFunctionConfiguration to reject the same wrongly-trusted role with "
        f"InvalidParameterValueException, got {update_code!r}"
    )
    assert update_message == _UNASSUMABLE_ROLE, (
        f"expected UpdateFunctionConfiguration message {_UNASSUMABLE_ROLE!r}, got {update_message!r}"
    )
    unchanged_config = lam.get_function_configuration(FunctionName=good_fn_name)
    assert unchanged_config["Role"] == good_role_arn, (
        f"expected the rejected UpdateFunctionConfiguration to leave the function's role at "
        f"{good_role_arn!r}, but an independent read now shows {unchanged_config['Role']!r}"
    )


def _error(fn):
    """The (code, message) a call is refused with; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _function_not_found(ctx, name: str) -> str:
    return f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"


def _lambda_zip_describe_iot_endpoint() -> bytes:
    src = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    iot = boto3.client('iot')\n"
        "    resp = iot.describe_endpoint(endpointType='iot:Data-ATS')\n"
        "    return {'endpointAddress': resp['endpointAddress']}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_role(ctx, principals, inline_policies=None, managed_policy_arns=None):
    iam = ctx.client("iam")
    principal = principals[0] if len(principals) == 1 else principals
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    name = ctx.unique_name("sim2real-iotlambda-role-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_name, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    for arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
    role = iam.get_role(RoleName=name)["Role"]
    return role["Arn"], name


def _delete_role(ctx, role_name) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_for_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        last_state = cfg.get("State")
        if last_state == "Active":
            return cfg
        if last_state == "Failed":
            raise RuntimeError(f"function {name} entered Failed state: {cfg}")
        time.sleep(2)
    raise TimeoutError(f"function {name} did not become Active (last state={last_state})")


def _create_function_with_retry(ctx, name, role_arn, zip_bytes, env=None, timeout_s=90.0):
    lam = ctx.client("lambda")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=30,
        Tags={"sim2real:managed": "true"},
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            return resp
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            last_err = e
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                time.sleep(3)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
