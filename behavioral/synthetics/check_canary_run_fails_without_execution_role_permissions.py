"""canary-run-fails-without-execution-role-permissions."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "canary-run-fails-without-execution-role-permissions"
GROUP = "overly-permissive"
SERVICES = ["synthetics"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A canary whose execution role grants nothing beyond the Lambda trust policy provisions to
    READY but its run FAILS and uploads no artifact; an identical canary with a permissioned role
    PASSES and uploads one, so the failure is caused by the missing permissions."""
    synth = ctx.client("synthetics")
    s3 = ctx.client("s3")
    bucket = _create_artifact_bucket(ctx)
    runtime = _latest_runtime_version(ctx)

    # Missing-permission boundary: a role that Lambda can assume but that grants nothing else.
    powerless_role = _create_execution_role(ctx, bucket, grant_permissions=False)
    bad_name = ctx.unique_name("sim2real-canary-nopolicy-").replace("_", "-")
    ctx.on_cleanup(lambda: _cleanup_canary(ctx, bad_name))
    bad_provision_state, bad_provision_status = _create_and_provision_canary(
        ctx, name=bad_name, bucket=bucket, role_arn=powerless_role, runtime=runtime,
        schedule_expr="rate(0 minute)", timeout_s=240,
    )
    assert bad_provision_state == "READY", (
        f"expected the powerless-role canary to still provision to READY (the trust policy alone "
        f"is enough for Lambda to assume it), got {bad_provision_state!r} "
        f"(StateReasonCode={bad_provision_status.get('StateReasonCode')!r}, "
        f"StateReason={bad_provision_status.get('StateReason')!r})"
    )
    synth.start_canary(Name=bad_name)
    bad_run_state, bad_run_status = _wait_for_run_terminal(ctx, bad_name, timeout_s=300)
    assert bad_run_state == "FAILED", (
        f"expected the run to FAIL without S3/logs permissions, got {bad_run_state!r} "
        f"(StateReasonCode={bad_run_status.get('StateReasonCode')!r}, "
        f"StateReason={bad_run_status.get('StateReason')!r})"
    )
    bad_objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert bad_objects == [], (
        f"expected no artifact to have been uploaded for the permission-less run, got {bad_objects!r}"
    )

    # Positive control: an otherwise identical canary with a properly permissioned role passes.
    good_role = _create_execution_role(ctx, bucket, grant_permissions=True)
    good_name = ctx.unique_name("sim2real-canary-withpolicy-").replace("_", "-")
    ctx.on_cleanup(lambda: _cleanup_canary(ctx, good_name))
    good_provision_state, good_provision_status = _create_and_provision_canary(
        ctx, name=good_name, bucket=bucket, role_arn=good_role, runtime=runtime,
        schedule_expr="rate(0 minute)", timeout_s=240,
    )
    assert good_provision_state == "READY", (
        f"expected the correctly-permissioned canary to provision to READY, got {good_provision_state!r} "
        f"(StateReasonCode={good_provision_status.get('StateReasonCode')!r}, "
        f"StateReason={good_provision_status.get('StateReason')!r})"
    )
    synth.start_canary(Name=good_name)
    good_run_state, good_run_status = _wait_for_run_terminal(ctx, good_name, timeout_s=300)
    assert good_run_state == "PASSED", (
        f"expected the correctly-permissioned canary to PASS, got {good_run_state!r} "
        f"(StateReasonCode={good_run_status.get('StateReasonCode')!r}, "
        f"StateReason={good_run_status.get('StateReason')!r})"
    )
    good_objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert good_objects, (
        "expected the correctly-permissioned run to upload an artifact (the bucket held none after "
        "the permission-less run, above), got none"
    )


def _wait_for_run_terminal(ctx, name: str, timeout_s: float) -> tuple[str, dict]:
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + timeout_s
    state = None
    status: dict = {}
    while time.monotonic() < deadline:
        runs = synth.get_canary_runs(Name=name)["CanaryRuns"]
        if runs:
            status = runs[0]["Status"]
            state = status["State"]
            if state in ("PASSED", "FAILED"):
                return state, status
        time.sleep(2)
    raise AssertionError(f"canary {name} run never reached a terminal state, last seen {state}")


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
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
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


def _create_execution_role(ctx, bucket_name: str, grant_permissions: bool) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-synth-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_iam_trust_policy(),
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
    for _ in range(10):
        try:
            return synth.create_canary(
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


def _delete_canary_and_wait_gone(ctx, name: str, timeout_s: float = 90.0) -> None:
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + 60
    while True:
        try:
            synth.delete_canary(Name=name, DeleteLambda=True)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            synth.get_canary(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(2)
    raise AssertionError(f"canary {name} still visible {timeout_s}s after delete_canary")


def _create_and_provision_canary(ctx, *, name, bucket, role_arn, runtime, schedule_expr,
                                  timeout_s: float = 240.0, propagation_s: float = 300.0) -> tuple[str, dict]:
    """Create the canary and wait for it to leave CREATING. Newly-created IAM roles can take a few
    seconds to propagate to Lambda; a canary that lands in ERROR purely because the role "cannot be
    assumed by Lambda" yet is a transient race, not the permissions boundary under test -- delete and
    retry so the eventual ERROR (if any) reflects the role's actual grants, not IAM propagation lag.
    """
    time_left = ctx.time_left()
    propagation_deadline = time.monotonic() + (propagation_s if time_left is None else min(propagation_s, time_left))
    while True:
        _create_canary_with_retry(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                                   schedule_expr=schedule_expr)
        state, status = _wait_for_canary_terminal_provision(ctx, name, timeout_s=timeout_s)
        reason = (status.get("StateReason") or "").lower()
        transient_iam_race = state == "ERROR" and "cannot be assumed by lambda" in reason
        if not transient_iam_race or time.monotonic() >= propagation_deadline:
            return state, status
        _delete_canary_and_wait_gone(ctx, name)


def _wait_for_canary_terminal_provision(ctx, name: str, timeout_s: float = 240.0,
                                         interval_s: float = 5.0) -> tuple[str, dict]:
    """Poll until the canary reaches READY (provisioned) or ERROR (provisioning failed)."""
    synth = ctx.client("synthetics")
    deadline = time.monotonic() + timeout_s
    status: dict = {}
    state = None
    while time.monotonic() < deadline:
        status = synth.get_canary(Name=name)["Canary"]["Status"]
        state = status["State"]
        if state in ("READY", "ERROR"):
            return state, status
        time.sleep(interval_s)
    raise AssertionError(f"canary {name} never reached READY or ERROR, last seen {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
