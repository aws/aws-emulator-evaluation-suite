"""rotation-after-cancel-rotate-secret-resumes-the-stuck-token-instead-of-the-requested-one."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotation-after-cancel-rotate-secret-resumes-the-stuck-token-instead-of-the-requested-one"
GROUP = "rotation"
SERVICES = ["secretsmanager"]

_MARKER = "sim2real-minted::"
_STUCK_MESSAGE = "A previous rotation isn't complete. That rotation will be reattempted."

# A four-step rotation function whose only variable is FAIL_STEP: the named step logs a marker and
# raises. Every other step is the documented protocol.
_LAMBDA_CODE = '''
import boto3, os, uuid

MARKER = os.environ["MINT_MARKER"]

def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")
    if os.environ.get("FAIL_STEP") == step:
        print("SIM2REAL_FAILED " + step + " " + token)
        raise RuntimeError("sim2real: deliberate failure in " + step)
    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            client.put_secret_value(
                SecretId=arn, ClientRequestToken=token,
                SecretString=MARKER + token + "::" + uuid.uuid4().hex,
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        return
    elif step == "testSecret":
        pending = client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        if not pending["SecretString"].startswith(MARKER + token):
            raise ValueError("pending value was not minted for this token")
    elif step == "finishSecret":
        staged = client.describe_secret(SecretId=arn)["VersionIdsToStages"]
        current = None
        for version, stages in staged.items():
            if "AWSCURRENT" in stages:
                if version == token:
                    return
                current = version
        client.update_secret_version_stage(
            SecretId=arn, VersionStage="AWSCURRENT",
            MoveToVersionId=token, RemoveFromVersionId=current,
        )
    else:
        raise ValueError("unknown step " + step)
'''


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A failed setSecret leaves AWSPENDING and refuses new rotations; after CancelRotateSecret the
    next RotateSecret resumes the stuck token, promotes its candidate, and mints no new version.
    """
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")

    fn_name = ctx.unique_name("sim2real-behav-stuckrot-fn-")
    # Registered FIRST so LIFO runs it LAST, after the function is gone and cannot re-flush logs.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn_name}"))

    created = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-stuckrot-"),
        SecretString="original-credential",
        Description="sim2real behavioral check: recovering a stuck rotation",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    original = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(sm, secret_arn))
    ctx.on_cleanup(lambda: _cancel_rotation(sm, secret_arn))

    role_arn = _create_rotation_role(ctx, secret_arn)
    fn_arn = _create_rotation_function(ctx, fn_name, role_arn, fail_step="setSecret")
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )

    def rotate(token):
        return sm.rotate_secret(
            SecretId=secret_arn,
            ClientRequestToken=token,
            RotationLambdaARN=fn_arn,
            RotationRules={"AutomaticallyAfterDays": 30},
            RotateImmediately=True,
        )

    stuck = str(uuid.uuid4())
    resp = _poll_ok(lambda: rotate(stuck), timeout_s=60.0)
    assert resp["VersionId"] == stuck, f"RotateSecret must echo its token; got {resp['VersionId']!r}"
    _poll(
        lambda: _failed_markers(ctx, fn_name),
        lambda seen: f"setSecret {stuck}" in seen,
        timeout_s=240.0,
        interval_s=4.0,
        description="the rotation function to fail its setSecret step",
    )

    described = sm.describe_secret(SecretId=secret_arn)
    assert described["VersionIdsToStages"] == {original: ["AWSCURRENT"], stuck: ["AWSPENDING"]}, (
        f"a failed setSecret must leave the candidate AWSPENDING beside the untouched AWSCURRENT; "
        f"got {described['VersionIdsToStages']!r}"
    )
    assert described.get("RotationEnabled") is True, f"rotation must be enabled; got {described!r}"
    assert "LastRotatedDate" not in described, (
        f"a rotation that never finished must not set LastRotatedDate; got {described.get('LastRotatedDate')!r}"
    )
    current = sm.get_secret_value(SecretId=secret_arn)
    assert (current["VersionId"], current["SecretString"]) == (original, "original-credential"), (
        f"AWSCURRENT must still serve the original credential; got {current['VersionId']!r}"
    )

    candidate = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPENDING")
    assert candidate["VersionId"] == stuck and candidate["SecretString"].startswith(_MARKER + stuck + "::"), (
        f"AWSPENDING must serve the value the function minted for the stuck token; got {candidate['VersionId']!r}"
    )

    code, message = _error(lambda: rotate(str(uuid.uuid4())))
    assert code == "InvalidRequestException", f"a new rotation while stuck must be refused; got {code!r}"
    assert message == _STUCK_MESSAGE, f"unexpected refusal message: {message!r}"

    # CancelRotateSecret turns rotation off but does not clean up the candidate.
    sm.cancel_rotate_secret(SecretId=secret_arn)
    cancelled = sm.describe_secret(SecretId=secret_arn)
    assert cancelled.get("RotationEnabled") is False, (
        f"CancelRotateSecret must disable rotation; got {cancelled.get('RotationEnabled')!r}"
    )
    assert cancelled["VersionIdsToStages"] == {original: ["AWSCURRENT"], stuck: ["AWSPENDING"]}, (
        f"CancelRotateSecret must leave the staging map as it was; got {cancelled['VersionIdsToStages']!r}"
    )
    # The operator repairs the function; a fresh rotation is now accepted despite the leftover label.
    lam.update_function_configuration(
        FunctionName=fn_name, Environment={"Variables": {"MINT_MARKER": _MARKER, "FAIL_STEP": ""}}
    )
    lam.get_waiter("function_updated_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    # The accepted rotation re-drives the stuck candidate's token, not the one this request named.
    fresh = str(uuid.uuid4())
    resp = rotate(fresh)
    assert resp["VersionId"] == stuck, (
        f"RotateSecret after the cancel must resume the stuck token {stuck!r}; got {resp['VersionId']!r}"
    )
    promoted = _poll(
        lambda: sm.get_secret_value(SecretId=secret_arn),
        lambda r: r["VersionId"] == stuck,
        timeout_s=240.0,
        interval_s=4.0,
        description="the resumed rotation to promote the stuck candidate",
    )
    assert promoted["SecretString"] == candidate["SecretString"], (
        "AWSCURRENT must hold the very value minted for the stuck token, not a new one"
    )
    final = _poll(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: d["VersionIdsToStages"].get(original) == ["AWSPREVIOUS"],
        timeout_s=60.0,
        interval_s=3.0,
        description="the original version to be demoted to AWSPREVIOUS",
    )
    # The function's finishSecret moves only AWSCURRENT, so the resumed candidate keeps AWSPENDING
    # too; the service adds and removes no label of its own.
    staged = {k: sorted(v) for k, v in final["VersionIdsToStages"].items()}
    assert staged == {original: ["AWSPREVIOUS"], stuck: ["AWSCURRENT", "AWSPENDING"]}, (
        f"the resumed candidate must be AWSCURRENT over the original; got {staged!r}"
    )
    assert final.get("RotationEnabled") is True, "the accepted rotation must re-enable rotation"
    assert "LastRotatedDate" in final, "a completed rotation must set LastRotatedDate"
    code, message = _error(lambda: sm.get_secret_value(SecretId=secret_arn, VersionId=fresh))
    assert code == "ResourceNotFoundException", f"the requested token must mint no version; got {code!r}"
    assert message == f"Secrets Manager can't find the specified secret value for VersionId: {fresh}", (
        f"unexpected not-found message: {message!r}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"waited {timeout_s}s for {description}; last observation: {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _poll_ok(fn, *, timeout_s, interval_s=3.0):
    """The first RotateSecret, retried only while the new invoke permission propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"RotateSecret was never permitted to invoke the function: {exc}")
            time.sleep(interval_s)


def _failed_markers(ctx, fn_name):
    logs = ctx.client("logs")
    seen, token = set(), None
    while True:
        kwargs = {"logGroupName": f"/aws/lambda/{fn_name}", "filterPattern": '"SIM2REAL_FAILED"'}
        if token:
            kwargs["nextToken"] = token
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return seen
            raise
        for e in resp.get("events", []):
            seen.add(e["message"].split("SIM2REAL_FAILED ", 1)[1].strip())
        token = resp.get("nextToken")
        if not token:
            return seen


def _create_rotation_role(ctx, secret_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-stuckrot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-rotate-inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "secretsmanager:DescribeSecret",
                            "secretsmanager:GetSecretValue",
                            "secretsmanager:PutSecretValue",
                            "secretsmanager:UpdateSecretVersionStage",
                        ],
                        "Resource": secret_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-rotate-inline"))
    return role["Role"]["Arn"]


def _create_rotation_function(ctx, fn_name, role_arn, *, fail_step):
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _LAMBDA_CODE)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=60,
                MemorySize=256,
                Environment={"Variables": {"MINT_MARKER": _MARKER, "FAIL_STEP": fail_step}},
                Tags={"sim2real": CHECK},
            )
        except ClientError as exc:
            # A new role is not assumable by Lambda for a few seconds; this bounded retry is what
            # makes role propagation correct.
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(3.0)
            continue
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
        lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return resp["FunctionArn"]
    raise AssertionError(f"rotation function never became creatable: {last}")


def _reap_log_group(ctx, group, rounds=6, interval_s=8.0):
    """delete_function does not remove the log group, and a buffered stream can re-create it after
    a delete. Delete, then watch for reappearance; stop after two consecutive absent reads."""
    logs = ctx.client("logs")
    absent_in_a_row = 0
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=group)
            absent_in_a_row = 0
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            absent_in_a_row += 1
            if absent_in_a_row >= 2:
                return
        time.sleep(interval_s)
    raise RuntimeError(f"log group {group} kept reappearing after {rounds} delete rounds")


def _cancel_rotation(sm, secret_id):
    try:
        sm.cancel_rotate_secret(SecretId=secret_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("ResourceNotFoundException", "InvalidRequestException"):
            raise


def _reap_secret(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message", "")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
