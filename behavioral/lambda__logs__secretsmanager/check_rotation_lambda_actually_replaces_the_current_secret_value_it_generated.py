"""rotation-lambda-actually-replaces-the-current-secret-value-it-generated."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotation-lambda-actually-replaces-the-current-secret-value-it-generated"

GROUP = "rotation"

SERVICES = ["lambda", "logs", "secretsmanager"]

_SCENARIO = "secretsmanager-rotation-replaces-current"

# The marker the rotation function stamps onto every value it mints. The check cannot predict the
# generated value -- that is the point -- but it can recognise it, which is what makes the assertion
# "AWSCURRENT holds the value the FUNCTION produced" rather than "AWSCURRENT changed".
_ROTATED_PREFIX = "sim2real-rotated::"

# A correct four-step rotation function for a generic (non-database) secret. Each step logs a marker
# line so the ORDER of delivery is observable in CloudWatch Logs -- nothing in any API response
# reports it.
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
        # No external system to update for a generic secret.
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
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RotateSecret runs the customer's function through all four steps: AWSCURRENT ends on the
    value it generated, the old version becomes AWSPREVIOUS byte-intact, one version holds
    AWSCURRENT throughout, and the function's logs show the steps in the documented order.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html
    """
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")

    secret_name = ctx.unique_name("sim2real-rotate-secret-")
    original_value = "pre-rotation-credential"
    created = sm.create_secret(
        Name=secret_name,
        SecretString=original_value,
        Description="sim2real behavioral check: rotation replaces AWSCURRENT",
        Tags=_sim2real_tags(_SCENARIO),
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, secret_arn))
    # A scheduled rotation can otherwise fire against a deleted target. LIFO: registered after the
    # reap, so it runs before it.
    ctx.on_cleanup(lambda: _cancel_rotation(ctx, secret_arn))

    original_version_id = created["VersionId"]
    staged_before = sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    assert staged_before == {original_version_id: ["AWSCURRENT"]}, (
        f"baseline: a fresh secret must hold exactly one AWSCURRENT version, saw {staged_before!r}"
    )

    role_arn = _create_rotation_role(ctx, secret_arn)
    fn_name, fn_arn = _create_rotation_function(ctx, role_arn)
    _grant_secretsmanager_invoke(ctx, fn_name, secret_arn)

    # Assert the function's resource policy is in place BEFORE rotating, so a resource-policy
    # propagation failure is not mistaken for a rotation that never ran.
    policy = json.loads(
        _poll_until(
            lambda: _get_function_policy(lam, fn_name),
            lambda p: p is not None,
            timeout_s=60.0,
            interval_s=2.0,
            description=f"the resource policy on {fn_name} to be readable",
        )
    )
    principals = {
        s.get("Principal", {}).get("Service") for s in policy.get("Statement", [])
    }
    assert "secretsmanager.amazonaws.com" in principals, (
        f"Secrets Manager must be permitted to invoke the rotation function before RotateSecret is "
        f"called, or a failure here is indistinguishable from a rotation that never ran: {policy!r}"
    )

    # --- act ------------------------------------------------------------------------------------
    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
        RotateImmediately=True,
    )

    # --- observe: poll the STAGING LABELS, not RotationEnabled (which flips immediately) --------
    # The one-AWSCURRENT invariant is sampled on every poll iteration, so it is graded across the
    # whole transition rather than only at its endpoints.
    current_holders_seen: list[int] = []

    def _staged():
        staged = sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
        current_holders_seen.append(
            sum(1 for labels in staged.values() if "AWSCURRENT" in labels)
        )
        return staged

    staged_after = _poll_until(
        _staged,
        lambda staged: any(
            "AWSCURRENT" in labels and version != original_version_id
            for version, labels in staged.items()
        ),
        timeout_s=180.0,
        interval_s=3.0,
        description="a NEW version to carry AWSCURRENT after the rotation function ran",
    )
    assert current_holders_seen and max(current_holders_seen) == 1 and min(current_holders_seen) == 1, (
        f"exactly one version must carry AWSCURRENT at every instant observed, saw counts "
        f"{current_holders_seen!r} over the transition"
    )
    promoted_version = next(
        version
        for version, labels in staged_after.items()
        if "AWSCURRENT" in labels and version != original_version_id
    )

    # Contrary to a natural reading of the docs, AWSPENDING is NOT released after finishSecret: the
    # promoted version keeps ['AWSCURRENT', 'AWSPENDING']. So the check asserts only that AWSPENDING
    # sits on the AWSCURRENT version and the demoted version carries exactly AWSPREVIOUS.
    staged_final = _poll_until(
        _staged,
        lambda staged: set(staged) == {promoted_version, original_version_id}
        and staged.get(original_version_id) == ["AWSPREVIOUS"],
        timeout_s=180.0,
        interval_s=3.0,
        description=(
            "the staging labels to settle to exactly two versions, the old one demoted to "
            "AWSPREVIOUS"
        ),
    )
    assert set(staged_final) == {promoted_version, original_version_id}, (
        f"a completed rotation must leave exactly two labelled versions, the promoted one and the "
        f"demoted one: {staged_final!r}"
    )
    assert staged_final[original_version_id] == ["AWSPREVIOUS"], (
        f"the pre-rotation version must be demoted to exactly AWSPREVIOUS -- it must keep neither "
        f"AWSCURRENT nor AWSPENDING: {staged_final!r}"
    )
    assert "AWSCURRENT" in staged_final[promoted_version], (
        f"the promoted version must carry AWSCURRENT: {staged_final!r}"
    )
    assert "AWSPENDING" not in staged_final[original_version_id], (
        f"AWSPENDING must never remain on a version that AWSCURRENT does not resolve to -- that is "
        f"the state an interrupted rotation leaves behind: {staged_final!r}"
    )

    new_current = sm.get_secret_value(SecretId=secret_arn)
    previous = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")

    assert new_current["VersionId"] != original_version_id, (
        f"rotation must mint a new version, but AWSCURRENT is still {original_version_id!r}"
    )
    assert new_current["SecretString"].startswith(_ROTATED_PREFIX), (
        f"AWSCURRENT does not hold the value the rotation FUNCTION generated (it must carry the "
        f"marker the function stamps): {new_current['SecretString']!r}"
    )
    assert new_current["SecretString"] != original_value, (
        f"the secret material did not change: {new_current['SecretString']!r}"
    )
    assert (
        previous["VersionId"] == original_version_id
        and previous["SecretString"] == original_value
    ), (
        f"AWSPREVIOUS must preserve the pre-rotation plaintext byte for byte: version "
        f"{previous['VersionId']!r} holding {previous['SecretString']!r}"
    )
    assert new_current["VersionId"] == promoted_version, (
        f"AWSCURRENT must resolve to the version the staging map promoted: "
        f"{new_current['VersionId']!r} != {promoted_version!r}"
    )

    # --- observe: the four Step values, in order, from the function's own log group -------------
    # Secrets Manager can retry the createSecret/setSecret/testSecret prefix, so only the terminal
    # cycle before finishSecret is guaranteed ordered, and finishSecret is delivered exactly once.
    steps_logged = _poll_until(
        lambda: _step_markers(ctx, fn_name),
        lambda steps: steps[-4:] == ["createSecret", "setSecret", "testSecret", "finishSecret"],
        timeout_s=180.0,
        interval_s=5.0,
        description="a clean createSecret, setSecret, testSecret, finishSecret cycle to close out the rotation function's log group",
    )
    assert steps_logged[-4:] == ["createSecret", "setSecret", "testSecret", "finishSecret"], (
        f"the rotation steps immediately preceding finishSecret were not delivered in the "
        f"documented order: {steps_logged!r}"
    )
    assert steps_logged.count("finishSecret") == 1, (
        f"finishSecret must be delivered exactly once even if Secrets Manager retried an earlier "
        f"step: {steps_logged!r}"
    )

    desc = sm.describe_secret(SecretId=secret_arn)
    assert desc["RotationEnabled"] is True and desc["RotationLambdaARN"] == fn_arn, (
        f"the secret must report rotation enabled against this function: "
        f"RotationEnabled={desc.get('RotationEnabled')!r} "
        f"RotationLambdaARN={desc.get('RotationLambdaARN')!r} (expected {fn_arn!r})"
    )
    assert desc["NextRotationDate"] > desc["LastRotatedDate"], (
        f"a completed rotation must schedule the next one after the one that just happened: "
        f"NextRotationDate={desc.get('NextRotationDate')!r} "
        f"LastRotatedDate={desc.get('LastRotatedDate')!r}"
    )


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
    """The ordered Step values the rotation function logged.

    Read with filter_log_events across the whole log group and sorted by timestamp, because a
    rotation can be retried and each attempt writes to a different log stream. Returns [] while the
    group does not exist yet -- it is created by the service on first invocation.
    """
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
    # Scoped to the ONE secret under test: a rotation function that could rewrite any secret in the
    # account would make every negative in this suite unfalsifiable.
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
    # IAM propagation exposes no condition to poll -- no API reports that a role has become
    # assumable. The bounded retry in _create_rotation_function is what makes this correct; no
    # unconditional sleep here.
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


def _create_rotation_function(
    ctx, role_arn: str, extra_env: dict[str, str] | None = None
) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-rotate-fn-")
    ctx.on_cleanup(lambda: _delete_function(ctx, fn_name))
    # The log group is created by the SERVICE on first invocation, so a delete registered here can
    # race the group into existence and lose. Registered anyway: it is the only handle.
    ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{fn_name}"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _LAMBDA_CODE)

    env = {"ROTATED_PREFIX": _ROTATED_PREFIX}
    env.update(extra_env or {})

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
            # A newly created role takes a few seconds to become assumable by Lambda. This bounded
            # retry -- not the sleep above -- is what makes the role propagation correct.
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
