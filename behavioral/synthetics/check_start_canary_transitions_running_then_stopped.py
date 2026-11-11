"""start-canary-transitions-running-then-stopped."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-canary-transitions-running-then-stopped"
GROUP = "state-machine"
SERVICES = ["synthetics"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartCanary on a one-shot schedule runs the canary once and settles CanaryState at STOPPED, with
    a PASSED run whose timeline starts and completes."""
    synth = ctx.client("synthetics")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    runtime = _latest_runtime_version(ctx)
    name = ctx.unique_name("sim2real-canary-").replace("_", "-")
    # Registered before creation: a role-propagation retry inside _create_canary_with_retry can
    # raise after a canary already exists, and cleanup must still find it.
    ctx.on_cleanup(lambda: _cleanup_canary(ctx, name))
    _create_canary_with_retry(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                               schedule_expr="rate(0 minute)")

    synth.start_canary(Name=name)

    # STARTING and RUNNING are transient and a trivial one-shot run may pass both between two
    # reads, so the run itself is proven from GetCanaryRuns below, not from a sampled state.
    final_state = _wait_for_canary_state(ctx, name, {"STOPPED", "ERROR"}, timeout_s=300, interval_s=2)
    assert final_state == "STOPPED", f"expected canary to settle at STOPPED after its one-shot run, got {final_state}"

    # CanaryState flips to STOPPED as soon as the run finishes, but the run record itself can lag
    # briefly behind that flip -- an immediate ListRuns can race it, so this is a bounded retry,
    # not a single call.
    runs_deadline = time.monotonic() + 60
    runs = []
    while time.monotonic() < runs_deadline:
        runs = synth.get_canary_runs(Name=name)["CanaryRuns"]
        if runs:
            break
        time.sleep(5)
    assert len(runs) >= 1, "expected at least one recorded canary run within 60s of reaching STOPPED"
    assert runs[0]["Status"]["State"] == "PASSED", (
        f"expected the trivial handler's run to PASS, got {runs[0]['Status']['State']!r}: "
        f"{runs[0]['Status'].get('StateReason')}"
    )
    timeline = runs[0].get("Timeline", {})
    assert timeline.get("Started") and timeline.get("Completed"), (
        f"expected the run's timeline to record when it started and completed, got {timeline!r}"
    )
    assert timeline["Completed"] >= timeline["Started"], (
        f"the run cannot complete before it starts: {timeline!r}"
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
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint on CreateBucket;
    # this is an API quirk of the call, not a pin of the check to that region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_iam_trust_policy(),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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
    last_reason = None
    time_left = ctx.time_left()
    deadline = time.monotonic() + (300 if time_left is None else min(300, time_left))
    while time.monotonic() < deadline:
        try:
            resp = synth.create_canary(
                Name=name,
                Code={"ZipFile": code, "Handler": handler},
                ArtifactS3Location=f"s3://{bucket}",
                ExecutionRoleArn=role_arn,
                Schedule={"Expression": schedule_expr},
                RuntimeVersion=runtime,
                Tags={"sim2real-check": CHECK},
            )
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(2)
                continue
            raise

        # CreateCanary returns success synchronously even though the underlying Lambda's
        # role-assumption check runs asynchronously while the canary is CREATING. IAM role
        # propagation exposes no condition to poll, so a freshly created role can fail that async
        # check once -- surfacing as CanaryState ERROR, never as an exception here. The fix is to
        # delete and recreate, not to retry the call that already
        # succeeded.
        try:
            _wait_for_canary_state(ctx, name, {"READY"}, timeout_s=240, interval_s=5)
            return resp
        except AssertionError as exc:
            last_reason = str(exc)
            if "cannot be assumed by Lambda" not in last_reason:
                raise
            synth.delete_canary(Name=name, DeleteLambda=True)
            while time.monotonic() < deadline:
                try:
                    synth.get_canary(Name=name)
                except ClientError as gone:
                    if gone.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
                    break
                time.sleep(2)
    raise AssertionError(
        f"canary {name} never reached READY after retrying the role-propagation race: "
        f"{last_reason or last_exc}"
    )


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
    raise AssertionError(
        f"canary {name} never reached {target_states}, last seen "
        f"{status and status.get('State')}: {status and status.get('StateReason')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
