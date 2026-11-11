"""start-canary-dry-run-independent-of-schedule."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-canary-dry-run-independent-of-schedule"
GROUP = "data-plane"
SERVICES = ["synthetics"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartCanaryDryRun executes a run outside the canary's main CanaryState: the dry run
    reaches a terminal status of its own while the canary itself never leaves READY/STOPPED."""
    synth = ctx.client("synthetics")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)

    # Not every non-deprecated runtime supports StartCanaryDryRun (observed on real AWS: the
    # newest syn-nodejs-puppeteer-8.0 rejects it) -- fall back through progressively older
    # candidates rather than assuming "latest" is dry-run-capable.
    candidates = _runtime_candidates(ctx)
    name = None
    dry_run = None
    unsupported = []
    for runtime in candidates[:3]:
        candidate_name = _create_ready_canary(ctx, bucket=bucket, role_arn=role_arn, runtime=runtime)
        try:
            dry_run = synth.start_canary_dry_run(Name=candidate_name)
        except ClientError as exc:
            if (exc.response["Error"]["Code"] == "ValidationException"
                    and "does not support StartCanaryDryRun" in exc.response["Error"]["Message"]):
                unsupported.append(runtime)
                continue
            raise
        name = candidate_name
        break
    assert name is not None, f"no runtime among {candidates[:3]} supports StartCanaryDryRun: {unsupported}"
    dry_run_id = dry_run["DryRunConfig"]["DryRunId"]

    # Poll the dry run to a terminal CanaryState while repeatedly confirming the *main* canary
    # never left READY -- the dry run must not affect the scheduled canary's own state. These
    # are deliberately two separate GetCanary calls: with DryRunId set, Status.State reflects
    # the dry run's OWN CanaryState lifecycle (CREATING -> RUNNING -> ... -> STOPPED/ERROR),
    # not the main canary's, and not the script's own pass/fail -- that is a *different* enum
    # (CanaryRunState: RUNNING/PASSED/FAILED) carried on the CanaryRun object, read below via
    # GetCanaryRuns. All observed on real AWS: the dry run settled at Status.State "STOPPED"
    # while its CanaryRun reported "PASSED".
    _IN_PROGRESS = {"CREATING", "STARTING", "RUNNING", "UPDATING", "STOPPING"}
    deadline = time.monotonic() + 240
    dry_state = None
    while time.monotonic() < deadline:
        main_state = synth.get_canary(Name=name)["Canary"]["Status"]["State"]
        assert main_state == "READY", f"main canary state changed to {main_state} during a dry run"
        dry_state = synth.get_canary(Name=name, DryRunId=dry_run_id)["Canary"]["Status"]["State"]
        if dry_state not in _IN_PROGRESS:
            break
        time.sleep(2)
    else:
        raise AssertionError(f"dry run for {name} never reached a terminal CanaryState, last seen {dry_state!r}")

    dry_runs = synth.get_canary_runs(Name=name, RunType="DRY_RUN")["CanaryRuns"]
    assert any(r.get("Status", {}).get("State") == "PASSED" for r in dry_runs), dry_runs

    real_runs = synth.get_canary_runs(Name=name, RunType="CANARY_RUN")["CanaryRuns"]
    assert real_runs == [], f"a dry run must not create a scheduled CANARY_RUN entry: {real_runs}"


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_iam_trust_policy(),
                            Tags=[{"Key": "env", "Value": "sim2real"}])
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


def _runtime_candidates(ctx, prefix: str = "syn-nodejs-puppeteer-") -> list[str]:
    """Non-deprecated runtime versions for `prefix`, newest first by the API's own
    ReleaseDate -- not list order or a numeric parse of VersionName, which do not track
    release order (observed on real AWS: syn-nodejs-puppeteer-9.1 released after 8.0)."""
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
                candidates.append(rv)
        token = resp.get("NextToken")
        if not token:
            break
    if not candidates:
        raise AssertionError(f"no non-deprecated runtime version found for prefix {prefix}")
    candidates.sort(key=lambda rv: rv["ReleaseDate"], reverse=True)
    return [rv["VersionName"] for rv in candidates]


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
                Tags={"env": "sim2real"},
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


class _TransientCanaryError(Exception):
    """The canary reached ERROR for a reason that is IAM-propagation-shaped, not a real defect."""


def _wait_for_canary_state(ctx, name: str, target_states: set[str], timeout_s: float = 180.0,
                            interval_s: float = 5.0) -> str:
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = synth.get_canary(Name=name)["Canary"]["Status"]
        state = status["State"]
        if state in target_states:
            return state
        if state == "ERROR":
            reason = status.get("StateReason") or ""
            detail = f"canary {name} entered ERROR while waiting for {target_states}: {reason} ({status.get('StateReasonCode')})"
            if "cannot be assumed" in reason or "InvalidParameterValue" in reason:
                raise _TransientCanaryError(detail)
            raise AssertionError(detail)
        time.sleep(interval_s)
    raise AssertionError(f"canary {name} never reached {target_states}, last seen {status}")


def _create_ready_canary(ctx, *, bucket: str, role_arn: str, runtime: str) -> str:
    """Create the canary and wait for READY, retrying past the transient race where the
    just-created execution role has not yet propagated far enough for Synthetics' own
    internal Lambda creation to assume it (surfaces as the canary landing in ERROR seconds
    after a successful CreateCanary, distinct from the synchronous retry in
    _create_canary_with_retry). A non-transient ERROR is not retried."""
    last_exc: Exception | None = None
    for attempt in range(6):
        name = ctx.unique_name("sim2real-canary-").replace("_", "-")
        _create_canary_with_retry(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                                   schedule_expr="rate(1 hour)")
        ctx.on_cleanup(lambda n=name: _cleanup_canary(ctx, n))
        try:
            _wait_for_canary_state(ctx, name, {"READY"}, timeout_s=60)
            return name
        except _TransientCanaryError as exc:
            last_exc = exc
            time.sleep(5 * (attempt + 1))
            continue
    raise AssertionError(f"canary never reached READY after retrying past IAM propagation: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
