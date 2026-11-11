"""rotation-with-a-failing-testsecret-step-rejected-and-awscurrent-never-moves."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotation-with-a-failing-testsecret-step-rejected-and-awscurrent-never-moves"

GROUP = "rotation"

SERVICES = ["lambda", "logs", "secretsmanager"]

_SCENARIO = "secretsmanager-rotation-failing-testsecret"

_ROTATED_PREFIX = "sim2real-rotated::"

# ONE rotation function source, deployed TWICE. The two deployments differ in exactly one thing: the
# FAIL_ON_TEST environment variable. That is what makes the pair a controlled experiment rather than
# two different programs -- every other byte of behaviour, permission and wiring is identical.
_LAMBDA_CODE = '''
import boto3, os, uuid

MARKER = os.environ["ROTATED_PREFIX"]
FAIL_ON_TEST = os.environ.get("FAIL_ON_TEST") == "1"

def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    print("SIM2REAL_STEP " + step)
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
        if FAIL_ON_TEST:
            # The credential does not work. A correct implementation must never make it current.
            raise RuntimeError("sim2real: testSecret rejects this candidate credential")
        pending = client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
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

# How long the check insists finishSecret does not happen. Justified POST HOC against the latency the
# positive control measures -- the final assertion requires this window to be at least three times
# the observed createSecret-to-promotion time, so the number is evidence, not a guess.
_GRACE_WINDOW_S = 60.0


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rotation function that raises in testSecret leaves AWSCURRENT on the original version and
    never reaches finishSecret, while the same function with only one environment variable changed
    promotes: an untested credential is never made current."""
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")

    secret_name = ctx.unique_name("sim2real-rotate-secret-")
    original_value = "working-credential-that-must-survive"
    created = sm.create_secret(
        Name=secret_name,
        SecretString=original_value,
        Description="sim2real behavioral check: a failing testSecret must not promote",
        Tags=_sim2real_tags(_SCENARIO),
    )
    secret_arn = created["ARN"]
    original_version_id = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, secret_arn))
    # A failed rotation can leave a retry scheduled. LIFO: registered after the reap, runs first.
    ctx.on_cleanup(lambda: _cancel_rotation(ctx, secret_arn))

    # ONE role shared by both functions: they need identical permissions, and sharing it removes the
    # only asymmetry that could otherwise explain a difference in outcome.
    role_arn = _create_rotation_role(ctx, secret_arn)
    fail_fn, fail_arn = _create_rotation_function(ctx, role_arn, fail_on_test=True)
    pass_fn, pass_arn = _create_rotation_function(ctx, role_arn, fail_on_test=False)
    _grant_secretsmanager_invoke(ctx, fail_fn, secret_arn)
    _grant_secretsmanager_invoke(ctx, pass_fn, secret_arn)

    for fn_name in (fail_fn, pass_fn):
        policy = json.loads(
            _poll_until(
                lambda n=fn_name: _get_function_policy(lam, n),
                lambda p: p is not None,
                timeout_s=60.0,
                interval_s=2.0,
                description=f"the resource policy on {fn_name} to be readable",
            )
        )
        principals = {s.get("Principal", {}).get("Service") for s in policy.get("Statement", [])}
        assert "secretsmanager.amazonaws.com" in principals, (
            f"Secrets Manager must be able to invoke {fn_name} before this check can distinguish "
            f"'testSecret rejected the candidate' from 'the function was never invocable': {policy!r}"
        )

    # --- act: rotate with the FAILING function ---------------------------------------------------
    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=fail_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )

    # Bound the negative by the observed step log, not by the clock alone: the conclusion is reached
    # once testSecret has been delivered and finishSecret has not followed within the grace window.
    _poll_until(
        lambda: _step_markers(ctx, fail_fn),
        lambda steps: "testSecret" in steps,
        timeout_s=240.0,
        interval_s=3.0,
        description="the failing function to reach its testSecret step",
    )

    grace_started = time.monotonic()
    steps_seen: list[str] = []
    while time.monotonic() - grace_started < _GRACE_WINDOW_S:
        steps_seen = _step_markers(ctx, fail_fn)
        assert "finishSecret" not in steps_seen, (
            f"finishSecret must never be reached after testSecret raised; after "
            f"{time.monotonic() - grace_started:.0f}s the failing function had logged {steps_seen!r}"
        )
        current_now = sm.get_secret_value(SecretId=secret_arn)
        assert current_now["VersionId"] == original_version_id, (
            f"a rotation whose testSecret raised promoted a new version after "
            f"{time.monotonic() - grace_started:.0f}s: {current_now['VersionId']!r} != "
            f"{original_version_id!r}"
        )
        time.sleep(5.0)
    grace_window_s = time.monotonic() - grace_started

    # (a) the step protocol stopped where it had to.
    assert steps_seen[:3] == ["createSecret", "setSecret", "testSecret"], (
        f"the first rotation cycle must deliver exactly createSecret, setSecret, testSecret before "
        f"stopping: {steps_seen!r}"
    )
    assert "finishSecret" not in steps_seen, (
        f"finishSecret must never be reached after testSecret raises: {steps_seen!r}"
    )

    # (b) the effect is absent: AWSCURRENT and its plaintext are untouched.
    current_after_fail = sm.get_secret_value(SecretId=secret_arn)
    assert current_after_fail["VersionId"] == original_version_id, (
        f"a rotation whose testSecret raised still promoted a new version: "
        f"{current_after_fail['VersionId']!r} != {original_version_id!r}"
    )
    assert current_after_fail["SecretString"] == original_value, (
        f"AWSCURRENT secret material changed despite a failed testSecret: "
        f"{current_after_fail['SecretString']!r} != {original_value!r}"
    )
    staged = sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    assert staged[original_version_id] == ["AWSCURRENT"], (
        f"the original version must still be the sole AWSCURRENT holder: {staged!r}"
    )
    pending_versions = [v for v, labels in staged.items() if "AWSPENDING" in labels]
    assert all("AWSCURRENT" not in staged[v] for v in pending_versions), (
        f"an untested candidate carries AWSCURRENT: {staged!r}"
    )
    assert sum(1 for labels in staged.values() if "AWSCURRENT" in labels) == 1, (
        f"exactly one version may carry AWSCURRENT: {staged!r}"
    )

    # --- (c) positive control: the identical function that does NOT fail testSecret --------------
    _cancel_rotation(ctx, secret_arn)
    _poll_until(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: not d.get("RotationEnabled", False),
        timeout_s=120.0,
        interval_s=3.0,
        description="rotation to be cancelled before the control rotation is requested",
    )

    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=pass_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )
    # The quantity the grace window must dominate is testSecret -> promotion, NOT the whole rotation.
    # The negative's window opened only AFTER testSecret had been delivered, so cold start, IAM
    # propagation and AWS's own pre-invocation scheduling delay had all already elapsed there too.
    # MEASURED: comparing against the whole-rotation latency instead (39.5s of which ~34s precedes
    # testSecret) demanded a 119s window to prove an absence that resolves in single-digit seconds.
    _poll_until(
        lambda: _step_markers(ctx, pass_fn),
        lambda steps: "testSecret" in steps,
        timeout_s=240.0,
        interval_s=2.0,
        description="the control function to reach its testSecret step",
    )
    test_observed_at = time.monotonic()
    current_after_control = _poll_until(
        lambda: sm.get_secret_value(SecretId=secret_arn),
        lambda r: r["VersionId"] != original_version_id,
        timeout_s=240.0,
        interval_s=2.0,
        description="the passing function to promote a new AWSCURRENT version",
    )
    promotion_latency_s = max(time.monotonic() - test_observed_at, 0.5)

    assert current_after_control["VersionId"] != original_version_id, (
        f"positive control: an identical function whose testSecret succeeds MUST promote: "
        f"{current_after_control!r}"
    )
    assert current_after_control["SecretString"].startswith(_ROTATED_PREFIX), (
        f"positive control: AWSCURRENT must hold the value the control function generated: "
        f"{current_after_control['SecretString']!r}"
    )
    control_steps = _poll_until(
        lambda: set(_step_markers(ctx, pass_fn)),
        lambda steps: {"createSecret", "setSecret", "testSecret", "finishSecret"} <= steps,
        timeout_s=180.0,
        interval_s=5.0,
        description="the control function to log all four steps including finishSecret",
    )
    assert "finishSecret" in control_steps, (
        f"positive control: the control function must reach finishSecret, which is exactly the step "
        f"the failing function never reached: {sorted(control_steps)!r}"
    )

    # The never-assertion is only as strong as the window is long, so prove it was long enough.
    assert grace_window_s >= 3.0 * promotion_latency_s, (
        f"the grace window ({grace_window_s:.0f}s) must be at least three times the measured "
        f"testSecret-to-promotion latency ({promotion_latency_s:.1f}s) for 'finishSecret never "
        f"happened' to be evidence rather than impatience; raise _GRACE_WINDOW_S"
    )


# ===== helpers =====


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _get_function_policy(lam, fn_name: str):
    try:
        return lam.get_policy(FunctionName=fn_name)["Policy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _step_markers(ctx, fn_name: str) -> list[str]:
    """The ordered Step values a rotation function logged, across every stream in its group. A retried
    rotation writes to a new stream, so the whole group is read and sorted by timestamp."""
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
    return [e["message"].split("SIM2REAL_STEP ", 1)[1].strip() for e in ordered]


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
    # IAM propagation exposes no condition to poll here; the bounded retry in
    # _create_rotation_function (deadline + sleep, catching InvalidParameterValueException) is what
    # actually makes this correct, so no sleep belongs in this function at all.
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


def _create_rotation_function(ctx, role_arn: str, *, fail_on_test: bool) -> tuple[str, str]:
    lam = ctx.client("lambda")
    kind = "fail" if fail_on_test else "pass"
    fn_name = ctx.unique_name(f"sim2real-rotate-fn-{kind}-")
    ctx.on_cleanup(lambda: _delete_function(ctx, fn_name))
    ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{fn_name}"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _LAMBDA_CODE)

    env = {"ROTATED_PREFIX": _ROTATED_PREFIX}
    if fail_on_test:
        env["FAIL_ON_TEST"] = "1"

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
                Environment={"Variables": env},
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
        if exc.response.get("Error", {}).get("Code") not in (
            "ResourceNotFoundException", "InvalidRequestException"
        ):
            raise


def _reap_secret(ctx, secret_id: str, timeout_s: float = 90.0) -> None:
    """Force-delete a secret and poll until it is really gone.

    ForceDeleteWithoutRecovery is mandatory: a plain DeleteSecret imposes a 7-30 day recovery
    window, so the secret would outlive the run and bill $0.40/month until reaped.
    """
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
