"""delete-canary-while-running-conflict-rejected."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-canary-while-running-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["synthetics"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCanary rejects a canary that is currently RUNNING with ConflictException;
    the canary is left intact, and it deletes cleanly once actually stopped."""
    synth = ctx.client("synthetics")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    runtime = _latest_runtime_version(ctx)
    name = ctx.unique_name("sim2real-canary-").replace("_", "-")
    ctx.on_cleanup(lambda: _cleanup_canary(ctx, name))
    # rate(1 minute) keeps the canary recurring so it stays busy long enough to attempt DeleteCanary.
    _create_canary_until_ready(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                                schedule_expr="rate(1 minute)")

    synth.start_canary(Name=name)
    # A recurring canary holds RUNNING until stopped, so the refusal below meets one fixed state.
    _wait_for_canary_state(ctx, name, {"RUNNING"}, timeout_s=180, interval_s=5)

    code, message = _expect_error(lambda: synth.delete_canary(Name=name))
    assert code == "ConflictException", f"expected ConflictException while running, got {code!r}"
    expected = "Canary is in a state that can't be deleted: RUNNING"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the canary must still exist.
    still_there = synth.get_canary(Name=name)["Canary"]
    assert still_there["Name"] == name

    # Positive control: once stopped, deletion succeeds.
    synth.stop_canary(Name=name)
    _wait_for_canary_state(ctx, name, {"STOPPED"}, timeout_s=180, interval_s=5)
    synth.delete_canary(Name=name, DeleteLambda=True)

    # Real AWS returns ResourceNotFoundException for GetCanary once the name is truly gone (not
    # ValidationException, which is what a missing/malformed Name argument gets).
    final_code, final_message = _wait_until_gone(ctx, name, timeout_s=120)
    assert final_code == "ResourceNotFoundException", f"expected the deleted canary to be gone, got {final_code!r}"
    expected = "Canary not found."
    assert final_message == expected, f"expected message {expected!r}, got {final_message!r}"

    # A mutation on the dead id fails too, through a different operation than the read above.
    mutate_code, mutate_message = _expect_error(lambda: synth.stop_canary(Name=name))
    assert mutate_code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted canary to fail too, got {mutate_code!r}")
    expected = "Canary not found."
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"


# ===== helpers =====

def _wait_until_gone(ctx, name: str, timeout_s: float) -> tuple[str, str | None]:
    """Poll GetCanary until it is refused; return that refusal's (code, message). Raises when
    the canary is still readable at the deadline."""
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            synth.get_canary(Name=name)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"canary {name} is still readable {timeout_s}s after DeleteCanary")
        time.sleep(5)


def _expect_error(fn):
    """Call fn(); assert it raises, and return the error (code, message). An unexpected SUCCESS raises,
    so an accepted call that AWS rejects is reported as an unexpected success rather than as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _iam_trust_policy() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-synth-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_execution_role(ctx, bucket_name: str, grant_permissions: bool = True) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-synth-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_iam_trust_policy())
    role_arn = role["Role"]["Arn"]
    if grant_permissions:
        statements = [
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetBucketLocation"],
             "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"]},
            {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
            {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
             "Condition": {"StringEquals": {"cloudwatch:namespace": "CloudWatchSynthetics"}}},
        ]
        iam.put_role_policy(
            RoleName=role_name, PolicyName="synthetics-exec",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="synthetics-exec")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _minimal_code_zip() -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("nodejs/node_modules/canary.js", "exports.handler = async () => { return 'ok'; };\n")
    return buf.getvalue()


def _latest_runtime_version(ctx, prefix: str = "syn-nodejs-puppeteer-") -> str:
    synth = ctx.client("synthetics")
    candidates = []
    token = None
    while True:
        kwargs = {"MaxResults": 20}
        if token:
            kwargs["NextToken"] = token
        resp = synth.describe_runtime_versions(**kwargs)
        for rv in resp["RuntimeVersions"]:
            if rv["VersionName"].startswith(prefix) and not rv.get("DeprecationDate"):
                candidates.append(rv["VersionName"])
        token = resp.get("NextToken")
        if not token:
            break
    if not candidates:
        raise AssertionError(f"no non-deprecated runtime version found for prefix {prefix}")
    return candidates[-1]


def _create_canary_with_retry(ctx, *, name, bucket, role_arn, runtime, schedule_expr,
                               code_bytes: bytes | None = None, handler: str = "canary.handler") -> dict:
    synth = ctx.client("synthetics")
    code = code_bytes if code_bytes is not None else _minimal_code_zip()
    last_exc = None
    for _ in range(10):
        try:
            return synth.create_canary(
                Name=name,
                Code={"ZipFile": code, "Handler": handler},
                ArtifactS3Location=f"s3://{bucket}",
                ExecutionRoleArn=role_arn,
                Schedule={"Expression": schedule_expr},
                RuntimeVersion=runtime,
            )
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"create_canary never succeeded (IAM propagation?): {last_exc}")


def _create_canary_until_ready(ctx, *, name, bucket, role_arn, runtime, schedule_expr,
                                overall_timeout_s: float = 180.0) -> None:
    """CreateCanary can return success and still leave the canary in ERROR moments later,
    because the just-created execution role has not yet propagated far enough for Lambda to
    assume it -- a recoverable IAM race, not a rejection. Delete the failed attempt and retry
    creation within a bounded overall deadline rather than trusting the first shot."""
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + overall_timeout_s
    backoff = 5.0
    while True:
        _create_canary_with_retry(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                                   schedule_expr=schedule_expr)
        state = _wait_for_canary_state(ctx, name, {"READY", "ERROR"},
                                       timeout_s=max(30.0, deadline - time.monotonic()))
        if state == "READY":
            return
        status = synth.get_canary(Name=name)["Canary"]["Status"]
        reason = f"{status.get('StateReasonCode')}: {status.get('StateReason')}"
        if "cannot be assumed" not in reason.lower() or time.monotonic() >= deadline:
            raise AssertionError(f"canary {name} entered ERROR after create: {reason}")
        synth.delete_canary(Name=name, DeleteLambda=True)
        _wait_until_gone(ctx, name, timeout_s=30)
        time.sleep(backoff)
        backoff = min(backoff * 2, 20.0)


def _cleanup_canary(ctx, name: str) -> None:
    """Stop the canary if it runs, then delete it once it settles; a missing canary is clean.
    ConflictException (a transition still in flight) is retried every 2 s to a deadline."""
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + 300
    stop_sent = False
    state = None
    while True:
        try:
            state = synth.get_canary(Name=name)["Canary"]["Status"]["State"]
            if state == "RUNNING" and not stop_sent:
                synth.stop_canary(Name=name)
                stop_sent = True
            elif state not in ("STOPPING", "RUNNING", "STARTING", "UPDATING", "CREATING", "DELETING"):
                synth.delete_canary(Name=name, DeleteLambda=True)
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"canary {name} still {state} at the cleanup deadline; not deleted")
        time.sleep(2)


def _wait_for_canary_state(ctx, name: str, target_states: set[str], timeout_s: float = 180.0,
                            interval_s: float = 5.0) -> str:
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + timeout_s
    status = {}
    while time.monotonic() < deadline:
        status = synth.get_canary(Name=name)["Canary"]["Status"]
        state = status["State"]
        if state in target_states:
            return state
        if state == "ERROR" and "ERROR" not in target_states:
            raise AssertionError(
                f"canary {name} entered ERROR waiting for {target_states}: "
                f"{status.get('StateReasonCode')} {status.get('StateReason')!r}")
        time.sleep(interval_s)
    raise AssertionError(
        f"canary {name} never reached {target_states}, last seen {status.get('State')}: "
        f"{status.get('StateReasonCode')} {status.get('StateReason')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
