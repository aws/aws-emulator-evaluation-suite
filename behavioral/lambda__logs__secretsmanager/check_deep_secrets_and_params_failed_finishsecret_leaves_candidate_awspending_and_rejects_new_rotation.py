"""deep-secrets-and-params-failed-finishsecret-leaves-candidate-awspending-and-rejects-new-rotation."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-secrets-and-params-failed-finishsecret-leaves-candidate-awspending-and-rejects-new-rotation"

GROUP = "rotation"

SERVICES = ["lambda", "logs", "secretsmanager"]

_SCENARIO = "deep-secrets-rotation-finish-failure"
_MARKER = "sim2real-minted::"

# A four-step rotation function whose ONLY variable is FAIL_STEP: when it names a step, that step
# raises after logging. Everything else -- minting, testing, promoting -- is the correct protocol.
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
    if os.environ.get("FAIL_STEP") == step:
        raise RuntimeError("sim2real: deliberate failure in " + step)

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
    "axis:rejection",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A failed finishSecret leaves AWSCURRENT on the original and the candidate staged AWSPENDING,
    a new-token rotation is refused with InvalidRequestException meanwhile, and re-driving the same
    token after the fix promotes that same candidate with the original as AWSPREVIOUS."""
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")

    fn_name = ctx.unique_name("sim2real-deep-rot-fn-")
    # Registered FIRST so LIFO runs it LAST, after the function is gone and cannot re-flush logs.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn_name}"))

    original_value = "working-credential-must-survive"
    created = sm.create_secret(
        Name=ctx.unique_name("sim2real-deep-rot-secret-"),
        SecretString=original_value,
        Description="sim2real behavioral check: a failed finishSecret leaves AWSPENDING staged",
        Tags=_sim2real_tags(),
    )
    secret_arn = created["ARN"]
    original_version = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, secret_arn))
    ctx.on_cleanup(lambda: _cancel_rotation(ctx, secret_arn))

    role_arn = _create_rotation_role(ctx, secret_arn)
    fn_arn = _create_rotation_function(ctx, fn_name, role_arn, fail_step="finishSecret")
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
    assert resp["VersionId"] == token, f"RotateSecret must echo the token: {resp['VersionId']!r}"

    # Barrier: the function REACHED finishSecret (and raised before touching any label). From that
    # point nothing in this rotation can legitimately move AWSCURRENT.
    records = _poll_until(
        lambda: _step_records(ctx, fn_name),
        lambda recs: any(r["step"] == "finishSecret" for r in recs),
        timeout_s=200.0, interval_s=3.0,
        description="the failing function to reach its finishSecret step",
    )
    first_cycle = [r["step"] for r in records][:4]
    assert first_cycle == ["createSecret", "setSecret", "testSecret", "finishSecret"], (
        f"the first cycle must run all four steps up to the failing finishSecret: {first_cycle!r}"
    )

    # --- (b) effect absent: AWSCURRENT did not move; the candidate is staged, not promoted ------
    staged = {k: sorted(v) for k, v in sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"].items()}
    assert staged == {original_version: ["AWSCURRENT"], token: ["AWSPENDING"]}, (
        f"a failed finishSecret must leave exactly {{orig: [AWSCURRENT], token: [AWSPENDING]}}: "
        f"{staged!r}"
    )
    current = sm.get_secret_value(SecretId=secret_arn)
    assert (current["VersionId"], current["SecretString"]) == (original_version, original_value), (
        f"AWSCURRENT must still serve the original bytes: {current['VersionId']!r} "
        f"{current['SecretString']!r}"
    )
    pending_by_stage = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPENDING")
    pending_by_id = sm.get_secret_value(SecretId=secret_arn, VersionId=token)
    minted = pending_by_stage["SecretString"]
    assert pending_by_stage["VersionId"] == token and minted.startswith(_MARKER + token + "::"), (
        f"AWSPENDING must hold the candidate the function minted for this token: "
        f"{pending_by_stage['VersionId']!r} {minted!r}"
    )
    assert pending_by_id["SecretString"] == minted and pending_by_id["VersionStages"] == ["AWSPENDING"], (
        f"a VersionId read of the candidate must match the AWSPENDING read: {pending_by_id!r}"
    )

    # --- (a) the refusal: a new rotation cannot start over an outstanding candidate --------------
    intruder = str(uuid.uuid4())
    code, message = _error(lambda: sm.rotate_secret(
        SecretId=secret_arn, ClientRequestToken=intruder, RotateImmediately=True
    ))
    assert code == "InvalidRequestException", (
        f"RotateSecret with a new token while a previous rotation is incomplete must be refused "
        f"with InvalidRequestException, got {code!r}: {message!r}"
    )
    assert message == "A previous rotation isn't complete. That rotation will be reattempted.", (
        f"the refusal must name the incomplete previous rotation, got {message!r}"
    )
    absent, absent_message = _error(lambda: sm.get_secret_value(SecretId=secret_arn, VersionId=intruder))
    assert absent == "ResourceNotFoundException", (
        f"the refused rotation must mint no version for its token, got {absent!r}: {absent_message!r}"
    )
    assert absent_message == f"Secrets Manager can't find the specified secret value for VersionId: {intruder}", (
        f"unexpected GetSecretValue not-found message: {absent_message!r}"
    )
    staged_again = {k: sorted(v) for k, v in sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"].items()}
    assert staged_again == staged, (
        f"the refused rotation must leave the staging map untouched: {staged_again!r} vs {staged!r}"
    )

    # --- (c) positive control: fix the ONE broken thing and re-drive the SAME token -------------
    lam.update_function_configuration(
        FunctionName=fn_name,
        Environment={"Variables": {"MINT_MARKER": _MARKER, "FAIL_STEP": ""}},
    )
    lam.get_waiter("function_updated").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    resumed = sm.rotate_secret(SecretId=secret_arn, ClientRequestToken=token, RotateImmediately=True)
    assert resumed["VersionId"] == token, (
        f"re-driving the stuck rotation must resume the same version, got {resumed['VersionId']!r}"
    )
    final = _poll_until(
        lambda: {k: sorted(v) for k, v in sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"].items()},
        lambda m: "AWSCURRENT" in m.get(token, []),
        timeout_s=200.0, interval_s=3.0,
        description="the fixed function to promote the stuck candidate to AWSCURRENT",
    )
    assert set(final) == {original_version, token} and final[original_version] == ["AWSPREVIOUS"], (
        f"completion must promote the SAME candidate and demote the original to AWSPREVIOUS, "
        f"minting no third version: {final!r}"
    )
    promoted = sm.get_secret_value(SecretId=secret_arn)
    assert (promoted["VersionId"], promoted["SecretString"]) == (token, minted), (
        f"AWSCURRENT must now be the stuck candidate with its exact minted bytes: "
        f"{promoted['VersionId']!r} {promoted['SecretString']!r}"
    )
    previous = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")
    assert (previous["VersionId"], previous["SecretString"]) == (original_version, original_value), (
        f"AWSPREVIOUS must be the original version byte-exact: {previous!r}"
    )


# ===== helpers =====


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


def _create_rotation_function(ctx, fn_name: str, role_arn: str, *, fail_step: str = "") -> str:
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
                Environment={"Variables": {"MINT_MARKER": _MARKER, "FAIL_STEP": fail_step}},
                Tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
            )
            ctx.on_cleanup(lambda: _delete_function(ctx, fn_name))
            lam.get_waiter("function_active").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
            return resp["FunctionArn"]
        except ClientError as exc:
            # A new role is not assumable by Lambda for a few seconds; this bounded retry is what
            # makes role propagation correct.
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


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message", "")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
