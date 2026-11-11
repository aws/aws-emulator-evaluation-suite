"""rotate-immediately-false-schedules-a-rotation-without-running-the-full-protocol."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotate-immediately-false-schedules-a-rotation-without-running-the-full-protocol"

GROUP = "rotation"

SERVICES = ["lambda", "logs", "secretsmanager"]

_SCENARIO = "secretsmanager-rotate-immediately-false"

_ROTATED_PREFIX = "sim2real-rotated::"

# testSecret tolerates a missing AWSPENDING version: RotateImmediately=False runs testSecret alone to
# validate the configuration, and a raise there would fail the scheduling call itself.
_LAMBDA_CODE = '''
import boto3, os, uuid

MARKER = os.environ["ROTATED_PREFIX"]

def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event.get("ClientRequestToken")
    step = event["Step"]
    print("SIM2REAL_STEP " + step + " " + str(token))
    client = boto3.client("secretsmanager")

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=MARKER + uuid.uuid4().hex,
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        return
    elif step == "testSecret":
        try:
            pending = client.get_secret_value(
                SecretId=arn, VersionId=token, VersionStage="AWSPENDING"
            )
        except client.exceptions.ResourceNotFoundException:
            # Configuration test: Secrets Manager runs this step with no pending version staged.
            print("SIM2REAL_TESTSECRET_NO_PENDING")
            return
        if not pending["SecretString"].startswith(MARKER):
            raise ValueError("pending value is not the one this function generated")
    elif step == "finishSecret":
        metadata = client.describe_secret(SecretId=arn)
        current_version = None
        for version, stages in metadata["VersionIdsToStages"].items():
            if "AWSCURRENT" in stages:
                if version == token:
                    return
                current_version = version
                break
        client.update_secret_version_stage(
            SecretId=arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version,
        )
    else:
        raise ValueError("Invalid step: %s" % step)
'''

@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RotateSecret(RotateImmediately=False) records the function and a NextRotationDate, runs at
    most testSecret, and leaves AWSCURRENT untouched; RotateImmediately=True then runs all four steps
    and replaces the value."""
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    secret_name = ctx.unique_name("sim2real-rotate-secret-")
    v1 = "scheduled-only-credential"
    created = sm.create_secret(
        Name=secret_name,
        SecretString=v1,
        Description="sim2real behavioral check: RotateImmediately=False schedules only",
        Tags=_sim2real_tags(_SCENARIO),
    )
    secret_arn = created["ARN"]
    v1_version = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, secret_arn))
    # The rotation is left scheduled, so cancel it; LIFO: registered after the reap, runs first.
    ctx.on_cleanup(lambda: _cancel_rotation(ctx, secret_arn))

    role_arn = _create_rotation_role(ctx, secret_arn)
    fn_name, fn_arn = _create_rotation_function(ctx, role_arn)
    _grant_secretsmanager_invoke(ctx, fn_name, secret_arn)

    # Lambda creates /aws/lambda/<fn> on first invocation; creating it up front makes an empty
    # observation mean "not invoked" rather than lazy creation.
    log_group = f"/aws/lambda/{fn_name}"
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: _delete_log_group(ctx, log_group))
    logs.put_retention_policy(logGroupName=log_group, retentionInDays=1)
    assert _log_group_exists(logs, log_group), (
        f"the log group {log_group!r} must exist before the scheduling call, or the absence of log "
        f"streams proves nothing"
    )

    policy = json.loads(
        _poll_until(
            lambda: _get_function_policy(lam, fn_name),
            lambda p: p is not None,
            timeout_s=_budget_s(ctx, 60.0), ctx=ctx,
            interval_s=2.0,
            description=f"the resource policy on {fn_name} to be readable",
        )
    )
    principals = {s.get("Principal", {}).get("Service") for s in policy.get("Statement", [])}
    assert "secretsmanager.amazonaws.com" in principals, (
        f"Secrets Manager must be permitted to invoke the function before either RotateSecret call, "
        f"or 'the function was never invoked' is a permissions bug rather than the behaviour under "
        f"test: {policy!r}"
    )

    before_schedule = _now_ms()
    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=False,
    )

    desc = sm.describe_secret(SecretId=secret_arn)
    assert desc["RotationEnabled"] is True and desc["RotationLambdaARN"] == fn_arn, (
        f"the scheduling call must record rotation as enabled against this function: "
        f"RotationEnabled={desc.get('RotationEnabled')!r} "
        f"RotationLambdaARN={desc.get('RotationLambdaARN')!r} (expected {fn_arn!r})"
    )
    assert desc["RotationRules"]["AutomaticallyAfterDays"] == 30, (
        f"the configured window must round-trip: {desc['RotationRules']!r}"
    )
    days_ahead = (desc["NextRotationDate"] - desc["CreatedDate"]).total_seconds() / 86400.0
    assert 0 < days_ahead <= 31, (
        f"NextRotationDate must fall inside the configured 30-day window; it is {days_ahead:.2f} "
        f"days after CreatedDate (NextRotationDate={desc.get('NextRotationDate')!r})"
    )

    # Read once here; the positive control below is the barrier for anything the scheduling call
    # set off later, since every step is logged with its rotation's token.
    observed_steps = set(_step_markers(ctx, fn_name))
    assert observed_steps <= {"testSecret"}, (
        f"RotateImmediately=False ran the rotation protocol: the function had logged "
        f"{sorted(observed_steps)!r}; only the testSecret configuration test is permitted"
    )

    assert "createSecret" not in observed_steps, (
        f"createSecret must never run for a scheduled-only rotation: {sorted(observed_steps)!r}"
    )
    assert "finishSecret" not in observed_steps, (
        f"finishSecret must never run for a scheduled-only rotation: {sorted(observed_steps)!r}"
    )

    unchanged = sm.get_secret_value(SecretId=secret_arn)
    assert unchanged["VersionId"] == v1_version and unchanged["SecretString"] == v1, (
        f"a scheduled-only rotation changed the secret material: version "
        f"{unchanged['VersionId']!r} holding {unchanged['SecretString']!r}, expected "
        f"{v1_version!r} holding {v1!r}"
    )
    # The configuration test stages a transient AWSPENDING version and removes it again; wait
    # until no version carries AWSPENDING before reading the final staging.
    staged = _poll_until(
        lambda: sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"],
        lambda v: not any("AWSPENDING" in stages for stages in v.values()),
        timeout_s=_budget_s(ctx, 120.0), ctx=ctx,
        interval_s=2.0,
        description="the configuration test's AWSPENDING version to be removed",
    )
    assert staged == {v1_version: ["AWSCURRENT"]}, (
        f"a scheduled-only rotation must leave exactly the original version, labelled AWSCURRENT: "
        f"{staged!r}"
    )

    sm.rotate_secret(SecretId=secret_arn, RotateImmediately=True)
    _poll_until(
        lambda: _step_markers(ctx, fn_name),
        lambda steps: "createSecret" in steps,
        timeout_s=_budget_s(ctx, 180.0), ctx=ctx,
        interval_s=2.0,
        description="the immediate rotation to log its createSecret step",
    )

    after_control = _poll_until(
        lambda: sm.get_secret_value(SecretId=secret_arn),
        lambda r: r["VersionId"] != v1_version,
        timeout_s=_budget_s(ctx, 180.0), ctx=ctx,
        interval_s=2.0,
        description="the immediate rotation to promote a new AWSCURRENT version",
    )
    assert after_control["SecretString"].startswith(_ROTATED_PREFIX), (
        f"positive control: RotateImmediately=True must actually rotate, and AWSCURRENT must hold the "
        f"value the FUNCTION generated: {after_control['SecretString']!r}"
    )
    assert after_control["SecretString"] != v1, (
        f"positive control: the secret material must have changed: {after_control['SecretString']!r}"
    )
    control_steps = _poll_until(
        lambda: set(_step_markers(ctx, fn_name)),
        lambda steps: {"createSecret", "setSecret", "testSecret", "finishSecret"} <= steps,
        timeout_s=_budget_s(ctx, 180.0), ctx=ctx,
        interval_s=2.0,
        description="all four Step values to appear once an immediate rotation is requested",
    )
    assert {"createSecret", "setSecret", "testSecret", "finishSecret"} <= control_steps, (
        f"positive control: an immediate rotation must run all four steps: {sorted(control_steps)!r}"
    )

    scheduled_steps = sorted(
        step for step, token in _step_records(ctx, fn_name)
        if token != after_control["VersionId"]
    )
    assert set(scheduled_steps) <= {"testSecret"}, (
        f"RotateImmediately=False ran the rotation protocol: besides the immediate rotation "
        f"{after_control['VersionId']!r}, the function logged {scheduled_steps!r}; only the "
        f"testSecret configuration test is permitted"
    )
    assert before_schedule < _now_ms(), "clock sanity: the run must have taken measurable time"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _log_group_exists(logs, group: str) -> bool:
    token = None
    while True:
        kwargs: dict = {"logGroupNamePrefix": group}
        if token:
            kwargs["nextToken"] = token
        resp = logs.describe_log_groups(**kwargs)
        if any(g["logGroupName"] == group for g in resp.get("logGroups", [])):
            return True
        token = resp.get("nextToken")
        if not token:
            return False


def _get_function_policy(lam, fn_name: str):
    try:
        return lam.get_policy(FunctionName=fn_name)["Policy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _step_markers(ctx, fn_name: str) -> list[str]:
    """The ordered Step values the rotation function logged, across every stream in its group."""
    return [step for step, _ in _step_records(ctx, fn_name)]


def _step_records(ctx, fn_name: str) -> list[tuple[str, str]]:
    """The ordered (Step, ClientRequestToken) pairs the rotation function logged."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    events = []
    token = None
    while True:
        kwargs: dict = {"logGroupName": group, "filterPattern": '"SIM2REAL_STEP"'}
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
    ordered = sorted(events, key=lambda e: (e["timestamp"], e.get("eventId", "")))
    fields = [e["message"].split("SIM2REAL_STEP ", 1)[1].split() for e in ordered]
    return [(f[0], f[1] if len(f) > 1 else "") for f in fields]


def _create_rotation_role(ctx, secret_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rotate-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=_sim2real_tags("secretsmanager-rotation"),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
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
    # IAM propagation exposes no condition to poll; the bounded retry in _create_rotation_function
    # absorbs it.
    return role["Role"]["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    _leaks: list = []
    iam = ctx.client("iam")
    for call in (
        lambda: [
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
            for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        ],
        lambda: [
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
            for p in iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            )
        ],
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("NoSuchEntity", "ResourceNotFoundException"):
                _leaks.append((f"tearing down role {role_name}: {code}: {exc}", exc))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


def _create_rotation_function(ctx, role_arn: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-rotate-fn-")
    ctx.on_cleanup(lambda: _delete_function(ctx, fn_name))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _LAMBDA_CODE)

    deadline = time.monotonic() + 90.0
    last_error = None
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
                Environment={"Variables": {"ROTATED_PREFIX": _ROTATED_PREFIX}},
                Tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
            )
            lam.get_waiter("function_active").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
            return fn_name, resp["FunctionArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            last_error = exc
            time.sleep(3.0)
    raise AssertionError(f"rotation function never became creatable: {last_error}")


def _delete_function(ctx, fn_name: str) -> None:
    try:
        ctx.client("lambda").delete_function(FunctionName=fn_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"delete_function({fn_name}): {exc}") from exc


def _delete_log_group(ctx, group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"delete_log_group({group}): {exc}") from exc


def _grant_secretsmanager_invoke(ctx, fn_name: str, secret_arn: str) -> None:
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-secretsmanager-invoke",
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
        SourceArn=secret_arn,
    )


def _cancel_rotation(ctx, secret_id: str) -> None:
    try:
        ctx.client("secretsmanager").cancel_rotate_secret(SecretId=secret_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("ResourceNotFoundException", "InvalidRequestException"):
            raise RuntimeError(f"cancel_rotate_secret({secret_id}): {code}: {exc}") from exc


def _reap_secret(ctx, secret_id: str, timeout_s: float = 90.0) -> None:
    """Force-delete a secret and poll until it is gone.

    A plain DeleteSecret imposes a 7-30 day recovery window, so the secret would outlive the run."""
    sm = ctx.client("secretsmanager")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code in ("ThrottlingException", "InternalServiceError", "InvalidRequestException"):
                time.sleep(3.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"delete_secret({secret_id}) failed with {code}: {exc}"
                ) from exc
            return
    while time.monotonic() < deadline:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(2.0)
    raise RuntimeError(f"secret {secret_id} still present {timeout_s}s after "
        f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
