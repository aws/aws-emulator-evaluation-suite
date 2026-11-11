"""rotation-schedule-expression-with-duration-places-next-rotation-in-the-window."""
from __future__ import annotations

import datetime
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, extra_tags=(), **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}, *extra_tags], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _refusal(fn):
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=150.0, interval_s=3.0):
    """Bounded poll; returns the last observation whether or not the predicate held."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


def _zip_bytes(code: str, filename: str = "lambda_function.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_function_with_retry(lam, func_name, role_arn, code_bytes, timeout_s=90.0, ctx=None):
    """CreateFunction, retried only while the new execution role has not propagated."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=func_name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.handler", Code={"ZipFile": code_bytes}, Timeout=30,
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_exc = exc
            time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("CreateFunction succeeding: the run budget ended first; not graded")
    raise AssertionError(f"CreateFunction never succeeded (role propagation?): {last_exc}")


def _delete_log_group(ctx, group, appear_s=20, timeout_s=30, quiet_s=10):
    """Delete the function's log group and keep it deleted for ``quiet_s``: the group is created
    by the service after an invocation and a late log batch can recreate it."""
    logs = ctx.client("logs")

    def _present():
        return any(g.get("logGroupName") == group for g in
                   logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", []))

    appear_deadline = time.monotonic() + appear_s
    while not _present():
        if time.monotonic() >= appear_deadline:
            return
        time.sleep(3)
    deadline = time.monotonic() + timeout_s
    absent_since = None
    while True:
        if _present():
            absent_since = None
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        elif absent_since is None:
            absent_since = time.monotonic()
        elif time.monotonic() - absent_since >= quiet_s:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"log group {group!r} kept reappearing for {timeout_s}s")
        time.sleep(3)


CHECK = "rotation-schedule-expression-with-duration-places-next-rotation-in-the-window"
GROUP = "rotation"
SERVICES = ["secretsmanager"]

# A rotation function that implements the four steps without touching any external system.
_ROTATION_LAMBDA_SOURCE = """
import boto3


def handler(event, context):
    client = boto3.client("secretsmanager")
    arn, token, step = event["SecretId"], event["ClientRequestToken"], event["Step"]
    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            current = client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
            client.put_secret_value(SecretId=arn, ClientRequestToken=token,
                                    SecretString=current["SecretString"], VersionStages=["AWSPENDING"])
    elif step == "finishSecret":
        meta = client.describe_secret(SecretId=arn)
        current = next(v for v, s in meta["VersionIdsToStages"].items() if "AWSCURRENT" in s)
        if current != token:
            client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT",
                                               MoveToVersionId=token, RemoveFromVersionId=current)
"""

_SCHEDULE = "cron(0 16 ? * SAT *)"
_DURATION = "3h"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _window_floor(at):
    """The earliest NextRotationDate a call at ``at`` allows: the start of the Saturday 16:00-19:00
    UTC window ``at`` falls inside, else ``at`` itself."""
    if at.weekday() == 5 and 16 <= at.hour < 19:
        return at.replace(hour=16, minute=0, second=0, microsecond=0)
    return at


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateSecret with a cron ScheduleExpression, a Duration and RotateImmediately=False enables
    rotation without moving AWSCURRENT, round-trips the rules, and sets NextRotationDate to the
    next Saturday inside the 16:00-19:00 UTC window they define."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-rotcron-")
    created = _create_secret(sm, ctx, name, SecretString="sim2real-not-a-real-secret")
    secret_arn = created["ARN"]

    role_name = ctx.unique_name("sim2real-behav-rotcron-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "rotation-cron-inline-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Resource": secret_arn, "Action": [
                "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue",
                "secretsmanager:DescribeSecret", "secretsmanager:UpdateSecretVersionStage"]},
            {"Effect": "Allow", "Resource": "*", "Action": [
                "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]},
        ],
    }))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    func_name = ctx.unique_name("sim2real-behav-rotcron-fn-")
    # Registered before the function, so LIFO removes the group after the function is gone.
    ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{func_name}"))
    func_arn = _create_function_with_retry(
        lam, func_name, role_arn, _zip_bytes(_ROTATION_LAMBDA_SOURCE), timeout_s=_budget_s(ctx, 90.0), ctx=ctx
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    active = _poll(lambda: lam.get_function_configuration(FunctionName=func_name),
                   lambda c: c.get("State") in ("Active", "Failed"),
                   timeout_s=_budget_s(ctx, 120.0), interval_s=1.0)
    if active.get("State") not in ("Active", "Failed") and _budget_spent(ctx):
        raise TimeoutError("the rotation function leaving Pending: the run budget ended first; not graded")
    assert active.get("State") == "Active", (
        f"the rotation function never became Active: State={active.get('State')!r}, "
        f"reason={active.get('StateReason')!r}"
    )
    lam.add_permission(
        FunctionName=func_name, StatementId="allow-secretsmanager-invoke",
        Action="lambda:InvokeFunction", Principal="secretsmanager.amazonaws.com", SourceArn=secret_arn,
    )

    rules = {"ScheduleExpression": _SCHEDULE, "Duration": _DURATION}
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        called_at = datetime.datetime.now(datetime.timezone.utc)
        try:
            sm.rotate_secret(SecretId=secret_arn, RotationLambdaARN=func_arn,
                             RotationRules=rules, RotateImmediately=False)
            break
        except ClientError as exc:
            # The function's invoke permission and role are eventually consistent.
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                if exc.response["Error"]["Code"] == "AccessDeniedException" and _budget_spent(ctx):
                    raise TimeoutError("RotateSecret accepting the rotation function: the run budget ended first; "
                                       "not graded") from exc
                raise
            time.sleep(1)

    desc = _poll(lambda: sm.describe_secret(SecretId=secret_arn),
                 lambda d: d.get("RotationEnabled") is True and "NextRotationDate" in d,
                 timeout_s=_budget_s(ctx, 60.0), interval_s=1.0)
    if not (desc.get("RotationEnabled") is True and "NextRotationDate" in desc) and _budget_spent(ctx):
        raise TimeoutError("DescribeSecret showing rotation enabled: the run budget ended first; not graded")
    assert desc.get("RotationEnabled") is True, "RotateSecret must enable rotation"
    assert desc["RotationLambdaARN"] == func_arn, "the rotation function must be recorded"
    got_rules = desc.get("RotationRules", {})
    assert (got_rules.get("ScheduleExpression"), got_rules.get("Duration")) == (_SCHEDULE, _DURATION), (
        f"the rotation rules must round-trip, got {got_rules!r}"
    )
    nxt = desc["NextRotationDate"].astimezone(datetime.timezone.utc)
    assert nxt.weekday() == 5, f"NextRotationDate must fall on a Saturday, got {nxt.isoformat()}"
    window_start = nxt.replace(hour=16, minute=0, second=0, microsecond=0)
    assert window_start <= nxt <= window_start + datetime.timedelta(hours=3), (
        f"NextRotationDate must lie in the 16:00-19:00 UTC window, got {nxt.isoformat()}"
    )
    assert _window_floor(called_at) <= nxt <= called_at + datetime.timedelta(days=7, hours=3), (
        f"NextRotationDate must be the next Saturday window after the call, got {nxt.isoformat()} "
        f"for a call at {called_at.isoformat()}"
    )

    # RotateImmediately=False: AWSCURRENT stays on the original version and value. (Whether a
    # test invocation leaves an AWSPENDING version depends on the customer's function, so it
    # is not asserted.)
    stages = sm.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    current = sorted(v for v, labels in stages.items() if "AWSCURRENT" in labels)
    assert current == [created["VersionId"]], (
        "a deferred rotation must leave AWSCURRENT on the created version"
    )
    value = sm.get_secret_value(SecretId=secret_arn)
    assert (value["VersionId"], value["SecretString"]) == (
        created["VersionId"], "sim2real-not-a-real-secret"), (
        "a deferred rotation must not change the current value"
    )
    assert "LastRotatedDate" not in desc, (
        f"a deferred rotation has not rotated, LastRotatedDate={desc.get('LastRotatedDate')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
