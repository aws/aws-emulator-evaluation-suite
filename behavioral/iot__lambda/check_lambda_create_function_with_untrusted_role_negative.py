"""lambda-create-function-with-untrusted-role-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-create-function-with-untrusted-role-negative"
GROUP = "iam-trust"
SERVICES = ["iot", "lambda"]

_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_UNASSUMABLE_ROLE = "The role defined for the function cannot be assumed by Lambda."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction with a role that trusts only iot.amazonaws.com fails InvalidParameterValueException with the
    exact message and creates nothing, while a role trusting lambda.amazonaws.com creates the function."""
    lam = ctx.client("lambda")

    iot_trusted_role_arn, _role_name = _create_role(ctx, ["iot.amazonaws.com"])
    bad_fn_name = ctx.unique_name("sim2real-iotlambda-fn-")

    code, message = _error(
        lambda: lam.create_function(
            FunctionName=bad_fn_name,
            Runtime="python3.12",
            Role=iot_trusted_role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": _lambda_zip_describe_iot_endpoint()},
            Timeout=30,
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for an iot-only-trusted role, got {code}"
    )
    assert message == _UNASSUMABLE_ROLE, (
        f"expected CreateFunction message {_UNASSUMABLE_ROLE!r}, got {message!r}"
    )
    get_code, get_message = _error(lambda: lam.get_function(FunctionName=bad_fn_name))
    assert get_code == "ResourceNotFoundException", (
        f"expected no function to have been created, but get_function returned {get_code}"
    )
    expected = _function_not_found(ctx, bad_fn_name)
    assert get_message == expected, f"expected get_function message {expected!r}, got {get_message!r}"

    # Positive control: a role that actually trusts lambda.amazonaws.com works fine.
    good_role_arn, _good_role_name = _create_role(
        ctx, ["lambda.amazonaws.com"], managed_policy_arns=[_BASIC_EXEC_POLICY]
    )
    good_fn_name = ctx.unique_name("sim2real-iotlambda-fn-")
    _create_function_with_retry(
        ctx, good_fn_name, good_role_arn, _lambda_zip_describe_iot_endpoint()
    )
    created_name = lam.get_function(FunctionName=good_fn_name)["Configuration"]["FunctionName"]
    assert created_name == good_fn_name, (
        f"expected get_function to report {good_fn_name!r}, got {created_name!r}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_function_with_retry(ctx, name, role_arn, zip_bytes, env=None, timeout_s=90.0):
    lam = ctx.client("lambda")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=30,
        Tags={"sim2real": CHECK},
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
