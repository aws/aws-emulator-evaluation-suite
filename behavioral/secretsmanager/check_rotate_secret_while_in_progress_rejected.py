"""rotate-secret-while-in-progress-rejected."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rotate-secret-while-in-progress-rejected"
GROUP = "server-side"
SERVICES = ["secretsmanager"]

_REACHED = {"Key": "sim2real-step", "Value": "finishSecret"}

# A rotation function that stages AWSPENDING in createSecret, tags the secret when it reaches
# finishSecret, and then raises there, so the candidate stays AWSPENDING beside AWSCURRENT.
_HANDLER = (
    "import boto3\n"
    "\n"
    "def lambda_handler(event, context):\n"
    "    arn, token, step = event['SecretId'], event['ClientRequestToken'], event['Step']\n"
    "    client = boto3.client('secretsmanager')\n"
    "    if step == 'createSecret':\n"
    "        try:\n"
    "            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage='AWSPENDING')\n"
    "        except client.exceptions.ResourceNotFoundException:\n"
    "            client.put_secret_value(SecretId=arn, ClientRequestToken=token,\n"
    "                                    SecretString='candidate-' + token, VersionStages=['AWSPENDING'])\n"
    "    elif step == 'finishSecret':\n"
    f"        client.tag_resource(SecretId=arn, Tags=[{_REACHED!r}])\n"
    "        raise RuntimeError('sim2real: deliberate finishSecret failure')\n"
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a rotation's AWSPENDING candidate sits on a version other than AWSCURRENT, RotateSecret with
    a new token is refused with InvalidRequestException, mints nothing and moves no label; a secret
    with no rotation outstanding accepts RotateSecret.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_RotateSecret.html
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-rotinprog-")
    created = sm.create_secret(
        Name=name,
        SecretString="original-current-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    original_version = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(sm, name))
    ctx.on_cleanup(lambda: _cancel_rotation(sm, name))
    lambda_arn = _deploy_rotation_lambda(ctx, created["ARN"])

    token = str(uuid.uuid4())
    sm.rotate_secret(
        SecretId=name,
        ClientRequestToken=token,
        RotationLambdaARN=lambda_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )
    _poll_until(
        lambda: sm.describe_secret(SecretId=name).get("Tags", []),
        lambda tags_: _REACHED in tags_,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=3.0,
    )
    staged = {k: sorted(v) for k, v in sm.describe_secret(SecretId=name)["VersionIdsToStages"].items()}
    assert staged == {original_version: ["AWSCURRENT"], token: ["AWSPENDING"]}, (
        f"expected AWSCURRENT on the original version and AWSPENDING on the candidate, got {staged}"
    )

    intruder = str(uuid.uuid4())
    code, message = _error(
        lambda: sm.rotate_secret(SecretId=name, ClientRequestToken=intruder, RotateImmediately=True)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}: {message!r}"
    assert message == "A previous rotation isn't complete. That rotation will be reattempted.", message
    code, message = _error(lambda: sm.get_secret_value(SecretId=name, VersionId=intruder))
    assert code == "ResourceNotFoundException", f"the refused rotation minted a version: {code!r}"
    assert message == f"Secrets Manager can't find the specified secret value for VersionId: {intruder}", message
    after = {k: sorted(v) for k, v in sm.describe_secret(SecretId=name)["VersionIdsToStages"].items()}
    assert after == staged, f"the refused rotation moved a label: {after} vs {staged}"

    # Positive control: a fresh secret with no outstanding rotation accepts the call.
    control_name = ctx.unique_name("sim2real-behav-rotinprog-ctrl-")
    sm.create_secret(
        Name=control_name,
        SecretString="control-current-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, control_name))
    sm.rotate_secret(
        SecretId=control_name,
        RotationLambdaARN=lambda_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=False,
    )
    control_desc = sm.describe_secret(SecretId=control_name)
    assert control_desc["RotationEnabled"] is True, f"control secret rotation not enabled: {control_desc}"
    assert control_desc["RotationLambdaARN"] == lambda_arn, (
        f"control secret rotation lambda {control_desc.get('RotationLambdaARN')!r} != {lambda_arn!r}"
    )


# ===== helpers =====
def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must be refused; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"the call was expected to be refused but succeeded: {result!r}")


def _cancel_rotation(sm, secret_id: str) -> None:
    try:
        sm.cancel_rotate_secret(SecretId=secret_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _reap_secret(sm, secret_id: str, timeout_s: float = 60.0) -> None:
    """Force-delete the secret, retrying while a cancelled rotation still holds it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _deploy_rotation_lambda(ctx, secret_arn: str) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-sm-rotinprog-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-rotate-inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-rotate-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:TagResource",
                ],
                "Resource": secret_arn,
            }],
        }),
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", _HANDLER)

    fn_name = ctx.unique_name("sim2real-sm-rotinprog-fn-")
    function_arn = None
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            function_arn = resp["FunctionArn"]
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(2)
    if function_arn is None:
        raise AssertionError(f"lambda never became creatable (IAM propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda state: state == "Active",
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=3.0,
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceAccount=account_id,
    )
    return function_arn


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
