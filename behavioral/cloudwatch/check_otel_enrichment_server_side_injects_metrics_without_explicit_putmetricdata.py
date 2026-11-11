"""otel-enrichment-server-side-injects-metrics-without-explicit-putmetricdata."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "otel-enrichment-server-side-injects-metrics-without-explicit-putmetricdata"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:cloudwatch-otel-enrichment", "resource:account-singleton:config-service-linked-recorder", "resource:account-singleton:observabilityadmin-telemetry-enrichment", "timing:real-time")
def run(ctx) -> None:
    """After enabling OTel enrichment and invoking a Lambda function, the AWS/Lambda
    "Invocations" metric appears via ListMetrics/GetMetricData purely as a side effect
    of the Lambda invocations -- the caller never issues PutMetricData for it."""
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    role_arn, role_name = _create_lambda_role(ctx)
    fn_name = ctx.unique_name("sim2real-cw-otel-fn-")
    ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
    _retry_until_ready(
        lambda: lam.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": _make_zip()},
            Timeout=10,
            Tags={"sim2real": CHECK},
        ),
        timeout_s=_budget_s(ctx, 90.0),
        ctx=ctx,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_active(ctx, fn_name, timeout_s=_budget_s(ctx, 60.0))

    baseline_status = cw.get_otel_enrichment()["Status"]
    ctx.on_cleanup(lambda: _restore_otel_status(cw, baseline_status))
    if baseline_status != "Running":
        _start_otel_with_prereq(ctx, cw)
    _poll_otel_status(cw, "Running", timeout_s=_budget_s(ctx, 90.0), ctx=ctx)

    start_time = datetime.now(timezone.utc) - timedelta(seconds=5)
    invocation_count = 5
    for _ in range(invocation_count):
        lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse")
    datetime.now(timezone.utc) + timedelta(minutes=1)

    dims = [{"Name": "FunctionName", "Value": fn_name}]
    found = _poll_until(
        lambda: bool(
            cw.list_metrics(Namespace="AWS/Lambda", MetricName="Invocations", Dimensions=dims)["Metrics"]
        ),
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=1.0,
    )
    if not found and _budget_spent(ctx):
        raise TimeoutError(
            "the AWS/Lambda Invocations metric in ListMetrics: the run budget ended first; not graded"
        )
    if not found:
        raise AssertionError(
            "AWS/Lambda Invocations metric never appeared via ListMetrics within the polling "
            "window -- real CloudWatch ingestion for service-vended metrics can take several "
            "minutes; increase the poll window to close this gap",
        )

    def _current_sum():
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "inv",
                    "MetricStat": {
                        "Metric": {"Namespace": "AWS/Lambda", "MetricName": "Invocations", "Dimensions": dims},
                        "Period": 300,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            ],
            StartTime=start_time,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        )
        values = resp["MetricDataResults"][0]["Values"]
        return sum(values) if values else 0.0

    # AWS/Lambda's Invocations metric is aggregated with a delay after each invocation;
    # poll (bounded) until the full expected count has landed rather than asserting on
    # a single snapshot.
    deadline = time.monotonic() + _budget_s(ctx, 300.0)
    total = _current_sum()
    while total < invocation_count and time.monotonic() < deadline:
        time.sleep(1)
        total = _current_sum()

    if total < invocation_count and _budget_spent(ctx):
        raise TimeoutError(
            f"Sum(Invocations) to reach {invocation_count}: the run budget ended first; not graded"
        )
    assert total == invocation_count, f"expected Sum(Invocations)={invocation_count} with no explicit PutMetricData, got {total}"


from botocore.exceptions import ClientError  # noqa: E402


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_otel_status(cw, expected, timeout_s=90.0, interval_s=1.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.get_otel_enrichment()["Status"]
        if last == expected:
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"OTel enrichment to reach {expected!r}: the run budget ended first; "
                           f"not graded")
    raise AssertionError(f"OTel enrichment never reached {expected!r}, last={last!r}")


def _restore_otel_status(cw, baseline):
    current = cw.get_otel_enrichment()["Status"]
    if current != baseline:
        if baseline == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()


def _start_otel_with_prereq(ctx, cw):
    """StartOTelEnrichment requires the account to have resource-tags-on-telemetry enabled
    first (observabilityadmin:StartTelemetryEnrichment). Enable it on demand if needed."""
    try:
        cw.start_otel_enrichment()
        return
    except ClientError:
        pass

    oa = ctx.client("observabilityadmin")
    # StartTelemetryEnrichment is idempotent: a repeat call on an account that already has
    # it enabled succeeds, so any refusal here is a real failure.
    try:
        oa.start_telemetry_enrichment()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            f"could not enable telemetry-enrichment prerequisite: {err.get('Code')}: {err.get('Message')!r}"
        ) from exc

    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    last_err = None
    while time.monotonic() < deadline:
        try:
            cw.start_otel_enrichment()
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError("StartOTelEnrichment to succeed after its prerequisite: the run budget "
                           "ended first; not graded") from last_err
    raise AssertionError(f"StartOTelEnrichment kept failing after enabling its prerequisite: {last_err}")


def _make_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _retry_until_ready(fn, timeout_s=90.0, interval_s=2.0, ctx=None):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("CreateFunction to accept the new role: the run budget ended first; "
                           "not graded") from last_err
    raise last_err


def _wait_active(ctx, fn_name, timeout_s=60.0, interval_s=1.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=fn_name)["Configuration"].get("State")
        if state == "Active":
            return
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"lambda {fn_name} to become Active: the run budget ended first; not graded")
    raise AssertionError("lambda function never became Active")


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cw-otel-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"], role_name


def _poll_until(predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval_s)
    return False


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
