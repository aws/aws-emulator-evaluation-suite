"""canary-run-completes-publishes-artifacts-and-metrics."""
from __future__ import annotations

import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "canary-run-completes-publishes-artifacts-and-metrics"
GROUP = "data-plane"
SERVICES = ["synthetics"]

_HEARTBEAT_JS = """
const synthetics = require('Synthetics');
const log = require('SyntheticsLogger');

const pageLoadBlueprint = async function () {
    const page = await synthetics.getPage();
    const response = await page.goto('https://docs.aws.amazon.com/', { waitUntil: 'domcontentloaded', timeout: 30000 });
    if (!response) {
        throw new Error('Failed to load page!');
    }
    await synthetics.takeScreenshot('loaded', 'loaded');
};

exports.handler = async () => {
    return await pageLoadBlueprint();
};
"""


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_metrics.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A started canary actually runs a Puppeteer script end to end: the run reaches PASSED,
    an artifact object lands in the configured S3 bucket, and CloudWatch Synthetics publishes
    a SuccessPercent metric datapoint for the canary."""
    synth = ctx.client("synthetics")
    s3 = ctx.client("s3")
    cw = ctx.client("cloudwatch")

    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    runtime = _latest_runtime_version(ctx)
    code = _heartbeat_code_zip()
    name = _create_ready_canary(
        ctx, bucket=bucket, role_arn=role_arn, runtime=runtime, code_bytes=code,
        handler="pageLoadBlueprint.handler", schedule_expr="rate(0 minute)",
    )

    synth.start_canary(Name=name)

    deadline = time.monotonic() + 360
    run_state = None
    while time.monotonic() < deadline:
        runs = synth.get_canary_runs(Name=name)["CanaryRuns"]
        if runs:
            run_state = runs[0]["Status"]["State"]
            if run_state in ("PASSED", "FAILED"):
                break
        time.sleep(10)
    assert run_state == "PASSED", f"expected the heartbeat canary run to PASS, got {run_state!r}"

    # Assert the run actually uploaded artifacts to the configured S3 bucket.
    objects = s3.list_objects_v2(Bucket=bucket, Prefix=f"canary/{name}/").get("Contents", [])
    if not objects:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert objects, f"expected at least one artifact object in s3://{bucket} after a PASSED run"

    # Assert CloudWatch Synthetics published a SuccessPercent datapoint for this canary.
    now = datetime.now(timezone.utc)
    metric_deadline = time.monotonic() + 240
    datapoints = []
    while time.monotonic() < metric_deadline:
        resp = cw.get_metric_statistics(
            Namespace="CloudWatchSynthetics",
            MetricName="SuccessPercent",
            Dimensions=[{"Name": "CanaryName", "Value": name}],
            StartTime=now - timedelta(minutes=15),
            EndTime=now + timedelta(minutes=5),
            Period=60,
            Statistics=["Average"],
        )
        datapoints = resp.get("Datapoints", [])
        if datapoints:
            break
        time.sleep(15)
    if not datapoints:
        raise AssertionError(
            "run PASSED and an artifact was confirmed in S3, but the SuccessPercent CloudWatch "
            "metric had not landed within 240s (CloudWatch metric ingestion latency)"
        )
    assert any(dp["Average"] == 100.0 for dp in datapoints), datapoints


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
        # us-east-1 is S3's API default and CreateBucket rejects an explicit LocationConstraint
        # naming it; this is not a region pin on ctx.region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "1"}]})

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
        RoleName=role_name, AssumeRolePolicyDocument=_iam_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": "1"}],
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


def _heartbeat_code_zip() -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("nodejs/node_modules/pageLoadBlueprint.js", _HEARTBEAT_JS)
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
                               code_bytes: bytes, handler: str) -> dict:
    synth = ctx.client("synthetics")
    last_exc = None
    for _ in range(10):
        try:
            return synth.create_canary(
                Name=name,
                Code={"ZipFile": code_bytes, "Handler": handler},
                ArtifactS3Location=f"s3://{bucket}",
                ExecutionRoleArn=role_arn,
                Schedule={"Expression": schedule_expr},
                RuntimeVersion=runtime,
                Tags={"sim2real": "1"},
            )
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"create_canary never succeeded (IAM propagation?): {last_exc}")


def _create_ready_canary(ctx, *, bucket, role_arn, runtime, code_bytes, handler, schedule_expr,
                          max_attempts: int = 4) -> str:
    """A freshly-created role can lose the race against Synthetics' own asynchronous provisioning:
    Synthetics creates the canary's Lambda function using role_arn immediately, and if IAM's trust
    policy has not propagated yet, that one-shot internal attempt fails and the canary goes straight
    to ERROR (StateReasonCode=CREATE_FAILED) without AWS retrying it. This is the same eventual
    consistency AWS documents for any fresh role handed to Lambda; recreating under a new name after
    a short backoff is the bounded retry, not a workaround for a real defect."""
    synth = ctx.client("synthetics")
    for attempt in range(max_attempts):
        name = ctx.unique_name("sim2real-canary-").replace("_", "-")
        _create_canary_with_retry(ctx, name=name, bucket=bucket, role_arn=role_arn, runtime=runtime,
                                   schedule_expr=schedule_expr, code_bytes=code_bytes, handler=handler)
        ctx.on_cleanup(lambda n=name: _cleanup_canary(ctx, n))
        try:
            _wait_for_canary_state(ctx, name, {"READY"}, timeout_s=240)
            return name
        except AssertionError:
            status = synth.get_canary(Name=name)["Canary"]["Status"]
            is_role_propagation = (
                status.get("StateReasonCode") == "CREATE_FAILED"
                and "assumed" in (status.get("StateReason") or "")
            )
            if not is_role_propagation or attempt == max_attempts - 1:
                raise
            time.sleep(20 * (attempt + 1))
    raise AssertionError(f"canary for role {role_arn} never became READY after {max_attempts} attempts")


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
        if status["State"] in target_states:
            return status["State"]
        if status["State"] == "ERROR" and "ERROR" not in target_states:
            break  # terminal: no amount of further polling turns ERROR into a target state
        time.sleep(interval_s)
    raise AssertionError(
        f"canary {name} never reached {target_states}, last seen {status.get('State')} "
        f"(reason={status.get('StateReason')!r} code={status.get('StateReasonCode')!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
