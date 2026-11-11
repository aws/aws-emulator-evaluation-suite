"""stop-canary-transitions-running-to-stopped."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-canary-transitions-running-to-stopped"
GROUP = "state-machine"
SERVICES = ["synthetics"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopCanary drives CanaryState RUNNING -> STOPPING -> STOPPED for a recurring schedule."""
    synth = ctx.client("synthetics")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    runtime = _latest_runtime_version(ctx)
    # rate(1 minute) is the fastest recurring schedule, so the canary keeps re-running until
    # explicitly stopped (unlike rate(0 minute), which self-stops after a single run).
    name = _create_ready_canary(ctx, bucket=bucket, role_arn=role_arn, runtime=runtime,
                                 schedule_expr="rate(1 minute)")

    synth.start_canary(Name=name)
    # StopCanary rejects a canary still in STARTING with ConflictException ("Canary is in a state
    # that can't be stopped"), so the wait must land on RUNNING specifically, not just "started".
    _wait_for_canary_state(ctx, name, {"RUNNING"}, timeout_s=180, interval_s=5)

    synth.stop_canary(Name=name)
    final_state = _wait_for_canary_state(ctx, name, {"STOPPED", "ERROR"}, timeout_s=180, interval_s=5)
    assert final_state == "STOPPED", f"expected STOPPED after explicit StopCanary, got {final_state}"

    # Assert the STOPPED state is durable, not a transient blip before resuming: three
    # independent reads spread 5s apart must all agree (freeze detector, not a bare wait).
    for _ in range(3):
        time.sleep(5)
        still_stopped = synth.get_canary(Name=name)["Canary"]["Status"]["State"]
        assert still_stopped == "STOPPED", f"canary reverted to {still_stopped} after being stopped"


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


def _create_ready_canary(ctx, *, bucket, role_arn, runtime, schedule_expr, propagation_s: float = 300.0) -> str:
    """Create a canary and wait for READY, retrying with a fresh name on CREATE_FAILED.

    `create_canary` accepting the request does not mean Lambda could assume the freshly-created
    role yet: IAM's own eventual consistency lands the canary in ERROR with StateReasonCode
    CREATE_FAILED ("The role defined for the function cannot be assumed by Lambda") well after the
    API call returned. Only that reason is retried, to a propagation deadline; any other ERROR fails.
    """
    synth = ctx.client("synthetics")
    time_left = ctx.time_left()
    deadline = time.monotonic() + (propagation_s if time_left is None else min(propagation_s, time_left))
    while True:
        name = ctx.unique_name("sim2real-canary-").replace("_", "-")
        _create_canary_with_retry(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                                   schedule_expr=schedule_expr)
        ctx.on_cleanup(lambda name=name: _cleanup_canary(ctx, name))
        state = _wait_for_canary_state(ctx, name, {"READY", "ERROR"}, timeout_s=240)
        if state == "READY":
            return name
        status = synth.get_canary(Name=name)["Canary"]["Status"]
        last_reason = f"{status.get('StateReasonCode')}: {status.get('StateReason')}"
        if "cannot be assumed by Lambda" not in (status.get("StateReason") or "") or time.monotonic() >= deadline:
            raise AssertionError(f"canary {name} never reached READY, last error: {last_reason}")
        try:
            synth.delete_canary(Name=name, DeleteLambda=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(2)


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
    status = None
    while time.monotonic() < deadline:
        status = synth.get_canary(Name=name)["Canary"]["Status"]
        if status["State"] in target_states:
            return status["State"]
        time.sleep(interval_s)
    reason = status.get("StateReason") if status else None
    reason_code = status.get("StateReasonCode") if status else None
    raise AssertionError(
        f"canary {name} never reached {target_states}, last seen "
        f"{status['State'] if status else None} (reason={reason_code}: {reason})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
