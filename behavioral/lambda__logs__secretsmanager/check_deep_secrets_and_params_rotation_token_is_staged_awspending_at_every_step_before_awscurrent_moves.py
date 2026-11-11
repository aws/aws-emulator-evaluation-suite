"""deep-secrets-and-params-rotation-token-is-staged-awspending-at-every-step-before-awscurrent-moves."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-secrets-and-params-rotation-token-is-staged-awspending-at-every-step-before-awscurrent-moves"

GROUP = "rotation"

SERVICES = ["lambda", "logs", "secretsmanager"]

_SCENARIO = "deep-secrets-rotation-staging-observed"
_MARKER = "sim2real-minted::"

# A correct four-step rotation function that, on entry to EVERY step, logs the staging map it sees.
# Only from inside the step are the in-flight labels observable; polling can race past a label that
# lived for one step.
_LAMBDA_CODE = '''
import boto3, json, os, uuid

MARKER = os.environ["MINT_MARKER"]

def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")
    staged = client.describe_secret(SecretId=arn)["VersionIdsToStages"]
    print("SIM2REAL_STEP " + json.dumps({"step": step, "token": token, "staged": staged}))

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
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
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RotateSecret's ClientRequestToken becomes the new VersionId, every rotation step sees it
    as AWSPENDING while the original holds AWSCURRENT, and AWSCURRENT moves only after finishSecret.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html
    """
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")

    fn_name = ctx.unique_name("sim2real-deep-rot-fn-")
    # Registered FIRST so LIFO runs it LAST, after the function is gone and cannot re-flush logs.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn_name}"))

    original_value = "pre-rotation-credential-é中"
    created = sm.create_secret(
        Name=ctx.unique_name("sim2real-deep-rot-secret-"),
        SecretString=original_value,
        Description="sim2real behavioral check: rotation staging observed per step",
        Tags=_sim2real_tags(),
    )
    secret_arn = created["ARN"]
    original_version = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, secret_arn))
    ctx.on_cleanup(lambda: _cancel_rotation(ctx, secret_arn))

    role_arn = _create_rotation_role(ctx, secret_arn)
    fn_arn = _create_rotation_function(ctx, fn_name, role_arn)
    _grant_secretsmanager_invoke(ctx, fn_name, secret_arn)
    _poll_until(
        lambda: _function_policy_principals(lam, fn_name),
        lambda p: "secretsmanager.amazonaws.com" in p,
        timeout_s=60.0, interval_s=2.0,
        description=f"Secrets Manager to be permitted to invoke {fn_name}",
    )

    token = str(uuid.uuid4())
    resp = sm.rotate_secret(
        SecretId=secret_arn,
        ClientRequestToken=token,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )
    assert resp["VersionId"] == token, (
        f"RotateSecret must return the caller's ClientRequestToken as the new VersionId: "
        f"{resp['VersionId']!r} != {token!r}"
    )

    final = _poll_until(
        lambda: sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"],
        lambda staged: "AWSCURRENT" in staged.get(token, []),
        timeout_s=200.0, interval_s=3.0,
        description=f"AWSCURRENT to move onto the rotation token {token}",
    )

    observed = _poll_until(
        lambda: _step_records(ctx, fn_name),
        lambda recs: [r["step"] for r in recs][-4:]
        == ["createSecret", "setSecret", "testSecret", "finishSecret"],
        timeout_s=120.0, interval_s=4.0,
        description="a complete createSecret..finishSecret cycle to reach the function's log group",
    )

    # Every step was handed this token, and saw AWSPENDING on it before AWSCURRENT moved.
    assert {r["token"] for r in observed} == {token}, (
        f"every step must receive the caller's token: {sorted({r['token'] for r in observed})!r}"
    )
    steps_seen = [r["step"] for r in observed]
    assert steps_seen[-4:] == ["createSecret", "setSecret", "testSecret", "finishSecret"], (
        f"the terminal cycle must be the four documented steps in order: {steps_seen!r}"
    )
    for rec in observed:
        if rec["step"] == "createSecret":
            continue  # the step that creates the pending version; its entry view is not asserted
        staged = {k: sorted(v) for k, v in rec["staged"].items()}
        assert "AWSPENDING" in staged.get(token, []), (
            f"on entry to {rec['step']} the token's version must carry AWSPENDING: {staged!r}"
        )
        assert "AWSCURRENT" not in staged.get(token, []), (
            f"on entry to {rec['step']} AWSCURRENT must NOT yet be on the token: {staged!r}"
        )
        assert "AWSCURRENT" in staged.get(original_version, []), (
            f"on entry to {rec['step']} the original version must still hold AWSCURRENT: {staged!r}"
        )

    # End state. AWSPENDING is not released from the token after finishSecret, so it is not
    # asserted absent.
    final = {k: sorted(v) for k, v in final.items()}
    assert set(final) == {original_version, token}, (
        f"a completed rotation must leave exactly the original and the token versions: {final!r}"
    )
    assert final[original_version] == ["AWSPREVIOUS"], (
        f"the original version must be demoted to exactly AWSPREVIOUS: {final!r}"
    )

    # VersionId reads and VersionStage reads agree, byte for byte, on both versions.
    default = sm.get_secret_value(SecretId=secret_arn)
    by_stage_current = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")
    by_id_token = sm.get_secret_value(SecretId=secret_arn, VersionId=token)
    assert default["VersionId"] == by_stage_current["VersionId"] == by_id_token["VersionId"] == token, (
        f"default, AWSCURRENT and VersionId=token must all resolve the token: "
        f"{default['VersionId']!r} {by_stage_current['VersionId']!r} {by_id_token['VersionId']!r}"
    )
    assert default["SecretString"] == by_stage_current["SecretString"] == by_id_token["SecretString"], (
        "the three reads of the current version must return identical bytes"
    )
    assert default["SecretString"].startswith(_MARKER + token + "::"), (
        f"AWSCURRENT must hold the value the function minted for THIS token: "
        f"{default['SecretString']!r}"
    )
    assert "AWSCURRENT" in by_id_token["VersionStages"], by_id_token["VersionStages"]

    prev_stage = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")
    prev_id = sm.get_secret_value(SecretId=secret_arn, VersionId=original_version)
    assert prev_stage["VersionId"] == prev_id["VersionId"] == original_version, (
        f"AWSPREVIOUS must resolve the original version: {prev_stage['VersionId']!r}"
    )
    assert prev_stage["SecretString"] == prev_id["SecretString"] == original_value, (
        f"the original plaintext must survive rotation byte-exact via both read forms: "
        f"{prev_stage['SecretString']!r} / {prev_id['SecretString']!r}"
    )
    assert prev_id["VersionStages"] == ["AWSPREVIOUS"], prev_id["VersionStages"]




def _sim2real_tags() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"waited {timeout_s}s for {description}; last observation: {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _step_records(ctx, fn_name: str) -> list[dict]:
    logs = ctx.client("logs")
    events, token = [], None
    while True:
        kwargs = {"logGroupName": f"/aws/lambda/{fn_name}", "filterPattern": '"SIM2REAL_STEP"'}
        if token:
            kwargs["nextToken"] = token
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return []
            raise
        events.extend(resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            break
    events.sort(key=lambda e: (e["timestamp"], e.get("eventId", "")))
    return [json.loads(e["message"].split("SIM2REAL_STEP ", 1)[1]) for e in events]


def _function_policy_principals(lam, fn_name: str) -> set:
    try:
        policy = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return set()
        raise
    return {s.get("Principal", {}).get("Service") for s in policy.get("Statement", [])}


def _create_rotation_role(ctx, secret_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-deep-rot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=_sim2real_tags())
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-rotate-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue",
                           "secretsmanager:PutSecretValue",
                           "secretsmanager:UpdateSecretVersionStage"],
                "Resource": secret_arn,
            }],
        }),
    )
    return role["Role"]["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    _leaks: list = []
    iam = ctx.client("iam")
    for call in (
        lambda: [iam.delete_role_policy(RoleName=role_name, PolicyName=p)
                 for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])],
        lambda: [iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_role_policies(RoleName=role_name).get(
                     "AttachedPolicies", [])],
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                _leaks.append((f"tearing down role {role_name}: {exc}", exc))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


def _create_rotation_function(ctx, fn_name: str, role_arn: str) -> str:
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _LAMBDA_CODE)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name, Runtime="python3.12", Role=role_arn,
                Handler="index.lambda_handler", Code={"ZipFile": buf.getvalue()},
                Timeout=60, MemorySize=256,
                Environment={"Variables": {"MINT_MARKER": _MARKER}},
                Tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
            )
            ctx.on_cleanup(lambda: _delete_function(ctx, fn_name))
            lam.get_waiter("function_active").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
            return resp["FunctionArn"]
        except ClientError as exc:
            # A new role is not assumable by Lambda for a few seconds after creation.
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"rotation function never became creatable: {last}")


def _delete_function(ctx, fn_name: str) -> None:
    try:
        ctx.client("lambda").delete_function(FunctionName=fn_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"delete_function({fn_name}): {exc}") from exc


def _reap_log_group(ctx, group: str, rounds: int = 6, interval_s: float = 8.0) -> None:
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
                raise RuntimeError(f"delete_log_group({group}): {exc}") from exc
            absent_in_a_row += 1
            if absent_in_a_row >= 2:
                return
        time.sleep(interval_s)
    raise RuntimeError(f"log group {group} kept reappearing after {rounds} delete rounds")


def _grant_secretsmanager_invoke(ctx, fn_name: str, secret_arn: str) -> None:
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="sim2real-secretsmanager-invoke",
        Action="lambda:InvokeFunction", Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )


def _cancel_rotation(ctx, secret_id: str) -> None:
    try:
        ctx.client("secretsmanager").cancel_rotate_secret(SecretId=secret_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "ResourceNotFoundException", "InvalidRequestException"
        ):
            raise RuntimeError(f"cancel_rotate_secret({secret_id}): {exc}") from exc


def _reap_secret(ctx, secret_id: str, timeout_s: float = 60.0) -> None:
    sm = ctx.client("secretsmanager")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code in ("ThrottlingException", "InternalServiceError", "InvalidRequestException"):
                time.sleep(3.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(f"delete_secret({secret_id}): {exc}") from exc
            return
    raise RuntimeError(f"secret {secret_id} could not be force-deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
