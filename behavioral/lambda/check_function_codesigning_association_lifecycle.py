"""function-codesigning-association-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "function-codesigning-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating/dissociating a CSC with a function updates ListFunctionsByCodeSigningConfig membership."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)
    profile_arn = _fake_signing_profile_arn(ctx)

    csc = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [profile_arn]},
    )["CodeSigningConfig"]
    csc_arn = csc["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn))

    lam.put_function_code_signing_config(CodeSigningConfigArn=csc_arn, FunctionName=fn["name"])
    ctx.on_cleanup(lambda: _detach_csc_ignore(lam, fn["name"]))

    fetched = lam.get_function_code_signing_config(FunctionName=fn["name"])
    assert fetched["CodeSigningConfigArn"] == csc_arn

    assert fn["arn"] in _list_functions_for_csc(lam, csc_arn), (
        "function not present in ListFunctionsByCodeSigningConfig after association"
    )

    lam.delete_function_code_signing_config(FunctionName=fn["name"])

    # Membership in ListFunctionsByCodeSigningConfig and the effect of
    # get_function_code_signing_config after dissociation are not guaranteed
    # to be immediately consistent, so poll with a bounded deadline instead of
    # asserting on the very next call.
    deadline = time.monotonic() + 60
    arns = _list_functions_for_csc(lam, csc_arn)
    while fn["arn"] in arns and time.monotonic() < deadline:
        time.sleep(2)
        arns = _list_functions_for_csc(lam, csc_arn)
    assert fn["arn"] not in arns, (
        "function still present in ListFunctionsByCodeSigningConfig after dissociation"
    )

    # On real AWS, once a function has no code signing config associated,
    # GetFunctionCodeSigningConfig does NOT raise -- the function itself
    # still exists, so there is no ResourceNotFoundException, and there is
    # no CodeSigningConfigArn to report a CodeSigningConfigNotFoundException
    # against either. Instead the call succeeds and the response simply no
    # longer contains a "CodeSigningConfigArn" entry. Poll (bounded) for
    # that instead of an exception.
    deadline = time.monotonic() + 60
    resp = lam.get_function_code_signing_config(FunctionName=fn["name"])
    while "CodeSigningConfigArn" in resp and time.monotonic() < deadline:
        time.sleep(2)
        resp = lam.get_function_code_signing_config(FunctionName=fn["name"])
    assert "CodeSigningConfigArn" not in resp, (
        f"function still reports a CodeSigningConfigArn after dissociation: {resp!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _fake_signing_profile_arn(ctx) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/SimRealAssocProfile/1"


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_basic_function(ctx) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
                Tags={"sim2real:managed": "true"},
            )
            break
        except Exception as e:  # role propagation delay
            if "cannot be assumed" in str(e) or "InvalidParameterValueException" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _wait_function_active(ctx, name: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last={cfg!r})")


def _list_functions_for_csc(lam, csc_arn: str) -> list:
    marker = None
    arns: list = []
    while True:
        kwargs = {"CodeSigningConfigArn": csc_arn, "MaxItems": 50}
        if marker:
            kwargs["Marker"] = marker
        resp = lam.list_functions_by_code_signing_config(**kwargs)
        arns.extend(resp.get("FunctionArns", []))
        marker = resp.get("NextMarker")
        if not marker:
            return arns


def _detach_csc_ignore(lam, function_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_function_code_signing_config(FunctionName=function_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "CodeSigningConfigNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
