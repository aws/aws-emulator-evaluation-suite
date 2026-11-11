"""update-canary-transitions-updating-to-update-complete."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-canary-transitions-updating-to-update-complete"
GROUP = "state-machine"
SERVICES = ["synthetics"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCanary drives CanaryState READY -> UPDATING -> READY with StateReasonCode UPDATE_COMPLETE."""
    synth = ctx.client("synthetics")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    runtime = _latest_runtime_version(ctx)
    name = ctx.unique_name("sim2real-canary-").replace("_", "-")
    schedule_expr = "rate(1 hour)"
    _create_canary_with_retry(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                               schedule_expr=schedule_expr)
    ctx.on_cleanup(lambda: _cleanup_canary(ctx, name))
    ready_state = _wait_ready_allowing_role_propagation(
        ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime, schedule_expr=schedule_expr,
    )
    assert ready_state == "READY", f"canary never settled at READY after create, got {ready_state}"

    before = synth.get_canary(Name=name)["Canary"]
    new_retention = (before.get("SuccessRetentionPeriodInDays") or 31) + 5
    synth.update_canary(Name=name, SuccessRetentionPeriodInDays=new_retention)

    final_state = _wait_for_canary_state(ctx, name, {"READY", "ERROR"}, timeout_s=180, interval_s=5)
    assert final_state == "READY", f"expected canary to settle at READY after update, got {final_state}"

    after = synth.get_canary(Name=name)["Canary"]
    assert after["Status"]["StateReasonCode"] == "UPDATE_COMPLETE", after["Status"]
    assert after["SuccessRetentionPeriodInDays"] == new_retention, (
        f"expected SuccessRetentionPeriodInDays to persist the update to {new_retention}, "
        f"got {after['SuccessRetentionPeriodInDays']}"
    )


# ===== helpers =====

def _iam_trust_policy() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-synth-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # us-east-1 is CreateBucket's own special case: it rejects a LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_iam_trust_policy(),
                            Tags=[{"Key": "sim2real", "Value": CHECK}])
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
                Tags={"sim2real": CHECK},
            )
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"create_canary never succeeded (IAM propagation?): {last_exc}")


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
    state = None
    while time.monotonic() < deadline:
        state = synth.get_canary(Name=name)["Canary"]["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"canary {name} never reached {target_states}, last seen {state}")


def _wait_ready_allowing_role_propagation(ctx, *, name, bucket, role_arn, runtime, schedule_expr,
                                           propagation_s: float = 300.0) -> str:
    """Waits for a freshly created canary to settle. A brand-new IAM role can trigger a
    transient ERROR ("role cannot be assumed by Lambda") purely from IAM eventual
    consistency; on that specific, recognized transient cause only, delete + recreate the
    canary with the same params and retry. Any other ERROR reason is returned as-is."""
    synth = ctx.client("synthetics")
    time_left = ctx.time_left()
    propagation_deadline = time.monotonic() + (propagation_s if time_left is None else min(propagation_s, time_left))
    while True:
        state = _wait_for_canary_state(ctx, name, {"READY", "ERROR"}, timeout_s=240)
        if state == "READY":
            return state
        status = synth.get_canary(Name=name)["Canary"]["Status"]
        reason = (status.get("StateReason") or "")
        if time.monotonic() >= propagation_deadline or "assumed by Lambda" not in reason:
            return state
        # Transient IAM propagation: delete and recreate the canary until the role propagates.
        synth.delete_canary(Name=name, DeleteLambda=True)
        deadline = time.monotonic() + 120
        while True:
            try:
                synth.get_canary(Name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"canary {name} still present 120s after delete")
            time.sleep(2)
        _create_canary_with_retry(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                                   schedule_expr=schedule_expr)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
