"""concurrent-reader-during-rotation-never-observes-a-broken-current-credential."""

from __future__ import annotations

import io
import json
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-reader-during-rotation-never-observes-a-broken-current-credential"

GROUP = "rotation"

SERVICES = ["lambda", "logs", "secretsmanager"]

_SCENARIO = "secretsmanager-reader-during-rotation"

_ROTATED_PREFIX = "sim2real-rotated::"

# AWSCURRENT resolution is eventually consistent across the read path, so a reader can still be
# served the OLD version for a few seconds after the promotion (e.g. the collapsed sequence
# [old, new, old, new] for one rotation). Convergence is therefore
# asserted only over a tail that starts this far past the promotion; the safety invariants are
# asserted at every instant, including inside the lag.
_CONVERGENCE_LAG_S = 15.0
_CONVERGENCE_WINDOW_S = 15.0

_LAMBDA_CODE = '''
import boto3, os, uuid

MARKER = os.environ["ROTATED_PREFIX"]

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


@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A reader polling AWSCURRENT throughout a rotation only ever sees the old or the new
    plaintext, staged AWSCURRENT, from a listed version and never empty, and converges on the new
    one; AWSCURRENT is eventually consistent, so it may briefly flip back after the promotion."""
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")

    secret_name = ctx.unique_name("sim2real-rotate-secret-")
    original_value = "credential-in-use-by-a-live-consumer"
    created = sm.create_secret(
        Name=secret_name,
        SecretString=original_value,
        Description="sim2real behavioral check: concurrent reader during rotation",
        Tags=_sim2real_tags(_SCENARIO),
    )
    secret_arn = created["ARN"]
    original_version_id = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, secret_arn))
    ctx.on_cleanup(lambda: _cancel_rotation(ctx, secret_arn))

    role_arn = _create_rotation_role(ctx, secret_arn)
    fn_name, fn_arn = _create_rotation_function(ctx, role_arn)
    _grant_secretsmanager_invoke(ctx, fn_name, secret_arn)

    policy = json.loads(
        _poll_until(
            lambda: _get_function_policy(lam, fn_name),
            lambda p: p is not None,
            timeout_s=60.0,
            interval_s=2.0,
            description=f"the resource policy on {fn_name} to be readable",
        )
    )
    principals = {s.get("Principal", {}).get("Service") for s in policy.get("Statement", [])}
    assert "secretsmanager.amazonaws.com" in principals, (
        f"Secrets Manager must be permitted to invoke the rotation function, or the reader would "
        f"sample a rotation that never happened: {policy!r}"
    )

    # The reader gets its OWN client: ctx.client caches per (service, endpoint, region, config,
    # creds), so sharing one would hand the same botocore client to two threads, and a botocore
    # client is not documented safe for concurrent use.
    reader_sm = ctx.client("secretsmanager", config=_reader_config())
    stop = threading.Event()
    # (monotonic_ts, version_id, secret_string, version_stages)
    observations: list[tuple[float, str, str, tuple[str, ...]]] = []
    throttled = [0]

    def _read_loop() -> None:
        while not stop.is_set():
            try:
                resp = reader_sm.get_secret_value(SecretId=secret_arn)
            except ClientError as exc:
                # GetSecretValue is rate-limited. A throttle is an expected gap in the sample, not a
                # failure -- it is counted, and the >= 50 assertion below is what stops a fully
                # throttled run from passing vacuously.
                if exc.response.get("Error", {}).get("Code") in (
                    "ThrottlingException",
                    "InternalServiceError",
                ):
                    throttled[0] += 1
                    time.sleep(0.2)
                    continue
                raise
            observations.append(
                (
                    time.monotonic(),
                    resp["VersionId"],
                    resp.get("SecretString") or "",
                    tuple(resp.get("VersionStages") or ()),
                )
            )
            time.sleep(0.05)

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(_read_loop)

        sm.rotate_secret(
            SecretId=secret_arn,
            RotationLambdaARN=fn_arn,
            RotationRules={"AutomaticallyAfterDays": 30},
            RotateImmediately=True,
        )
        # Poll to completion on the MAIN thread. The reader keeps sampling throughout, so the sample
        # straddles the transition by construction rather than by luck.
        _poll_until(
            lambda: sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"],
            lambda staged: any(
                "AWSCURRENT" in labels and version != original_version_id
                for version, labels in staged.items()
            ),
            timeout_s=240.0,
            interval_s=2.0,
            description="the rotation to promote a new AWSCURRENT version",
        )
        promotion_observed_at = time.monotonic()
        final_read = sm.get_secret_value(SecretId=secret_arn)
        final_value = final_read["SecretString"]
        # Keep sampling well past the promotion. MEASURED: a reader can still be served the OLD
        # version for a few seconds after the promotion, so the convergence assertion is made only
        # over the tail that begins _CONVERGENCE_LAG_S after it -- everything before that is graded by
        # the safety invariants, which hold at every instant. Bounded by the same deadline either way;
        # the only early exit is the reader thread already having died, so we surface that failure
        # via the `finally` block instead of burning the rest of the window first.
        sampling_deadline = time.monotonic() + _CONVERGENCE_LAG_S + _CONVERGENCE_WINDOW_S
        while time.monotonic() < sampling_deadline and not future.done():
            time.sleep(1.0)
    finally:
        # Stopped in a finally block, NOT via on_cleanup: on_cleanup runs after an assertion failure
        # has already propagated, which would leave a thread calling GetSecretValue against a secret
        # that is about to be deleted.
        stop.set()
        try:
            future.result(timeout=30)
        except Exception as exc:  # noqa: BLE001 - a reader failure must surface, not be swallowed
            executor.shutdown(wait=False)
            raise AssertionError(f"the reader thread failed: {exc!r}") from exc
        executor.shutdown(wait=True)

    assert final_value.startswith(_ROTATED_PREFIX), (
        f"the rotation must have produced the function's own value, or this check sampled something "
        f"other than a real rotation: {final_value!r}"
    )
    assert final_value != original_value, (
        f"the secret material must have changed for the transition assertion to mean anything: "
        f"{final_value!r}"
    )

    assert len(observations) >= 50, (
        f"the reader thread must have produced a real sample; only {len(observations)} reads "
        f"completed ({throttled[0]} throttled)"
    )

    seen_strings = [value for _, _, value, _ in observations]
    allowed = {original_value, final_value}

    # --- the SAFETY invariant, asserted at every instant sampled --------------------------------
    unexpected = sorted(set(seen_strings) - allowed)
    assert not unexpected, (
        f"a reader observed a value that is neither the old nor the new credential: {unexpected!r} "
        f"(allowed {sorted(allowed)!r}) across {len(seen_strings)} reads"
    )
    empty = sum(1 for value in seen_strings if not value)
    assert empty == 0, (
        f"no read may return an empty or missing SecretString; {empty} of {len(seen_strings)} were "
        f"empty"
    )
    bad_stages = [o for o in observations if "AWSCURRENT" not in o[3]]
    assert not bad_stages, (
        f"a default GetSecretValue returned a version not staged AWSCURRENT: {bad_stages[:3]!r}"
    )
    staged_final = sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    seen_versions = {version for _, version, _, _ in observations}
    assert seen_versions <= set(staged_final), (
        f"the reader resolved AWSCURRENT to a version the secret does not list: "
        f"{sorted(seen_versions - set(staged_final))!r} (staged {staged_final!r})"
    )

    # --- the sample must straddle the rotation, or nothing above was tested ---------------------
    collapsed = _collapse(seen_strings)
    transitions = len(collapsed) - 1
    assert transitions >= 1, (
        f"the reader observed no change at all, so it did not sample across the rotation; collapsed "
        f"sequence {[_short(v, original_value, final_value) for v in collapsed]!r}"
    )
    assert seen_strings[0] == original_value, (
        f"the sample must begin before the promotion: it opened with "
        f"{_short(seen_strings[0], original_value, final_value)!r}"
    )
    assert original_value in seen_strings and final_value in seen_strings, (
        f"the sample must straddle the rotation or the check proved nothing; distinct values seen: "
        f"{sorted({_short(v, original_value, final_value) for v in seen_strings})!r}"
    )

    # --- CONVERGENCE: past the measured lag, every read is the new credential -------------------
    tail = [
        o for o in observations if o[0] >= promotion_observed_at + _CONVERGENCE_LAG_S
    ]
    assert len(tail) >= 20, (
        f"the convergence tail must be a real sample: only {len(tail)} reads landed more than "
        f"{_CONVERGENCE_LAG_S:.0f}s after the promotion ({throttled[0]} throttled overall)"
    )
    tail_values = {value for _, _, value, _ in tail}
    assert tail_values == {final_value}, (
        f"the reader must CONVERGE on the new credential and stay there: over the "
        f"{_CONVERGENCE_WINDOW_S:.0f}s tail beginning {_CONVERGENCE_LAG_S:.0f}s after the promotion it "
        f"still served "
        f"{sorted(_short(v, original_value, final_value) for v in tail_values)!r}"
    )

    # --- an INDEPENDENT side-channel confirms the four-step state machine actually ran ----------
    # The reader-side assertions above prove the observable EFFECT of the rotation; they cannot tell
    # a rotation that ran createSecret/setSecret/testSecret/finishSecret from one that skipped a step
    # and still happened to leave AWSCURRENT pointing somewhere plausible. CloudWatch Logs is that
    # independent channel: the lambda prints its own step name on every invocation.
    logs_client = ctx.client("logs")
    log_group_name = f"/aws/lambda/{fn_name}"
    required_steps = {"createSecret", "setSecret", "testSecret", "finishSecret"}
    observed_steps = _poll_until(
        lambda: _observed_step_markers(logs_client, log_group_name),
        lambda steps: required_steps <= steps,
        timeout_s=90.0,
        interval_s=5.0,
        description="the rotation lambda's SIM2REAL_STEP markers to reach CloudWatch Logs",
    )
    assert required_steps <= observed_steps, (
        f"the rotation lambda's own CloudWatch Logs must show all four staging-label protocol steps "
        f"ran, or this cross-service check's inclusion of `logs` asserts nothing: only saw "
        f"{sorted(observed_steps)!r}"
    )


# ===== helpers =====


def _extract_step(message: str) -> str | None:
    marker = "SIM2REAL_STEP "
    idx = message.find(marker)
    if idx == -1:
        return None
    return message[idx + len(marker) :].strip()


def _observed_step_markers(logs_client, log_group_name: str) -> set[str]:
    try:
        events = logs_client.filter_log_events(
            logGroupName=log_group_name, filterPattern='"SIM2REAL_STEP"'
        ).get("events", [])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return set()
        raise
    return {step for e in events if (step := _extract_step(e["message"])) is not None}


def _short(value: str, original: str, final: str) -> str:
    if value == original:
        return "<old>"
    if value == final:
        return "<new>"
    return value


def _collapse(values: list[str]) -> list[str]:
    """Collapse runs of equal consecutive values, so len(result) - 1 is the number of transitions."""
    out: list[str] = []
    for value in values:
        if not out or out[-1] != value:
            out.append(value)
    return out


def _reader_config():
    """A distinct botocore Config makes the reader's client a distinct cache entry, so the reader
    thread and the main thread never share one botocore client."""
    from botocore.config import Config

    return Config(retries={"max_attempts": 2, "mode": "standard"})


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
    # IAM propagation exposes no condition to poll. The bounded retry in _create_rotation_function
    # (below) is what makes this correct; nothing here should be a naked sleep in front of it.
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
    ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{fn_name}"))

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
