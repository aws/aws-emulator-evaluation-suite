"""batch-get-metrics-malformed-resource-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-get-metrics-malformed-resource-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-metrics"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A MetricQuery with a non-ARN ResourceArn fails the whole BatchGetMetrics call with
    ValidationException 'Invalid SageMaker ARN', while a query on the real trial component returns
    Complete with the written value 4.0."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[{"MetricName": "ranged", "Timestamp": now, "Step": 0, "Value": 4.0}],
    )
    assert not put_resp.get("Errors"), f"unexpected batch_put_metrics errors: {put_resp.get('Errors')}"

    valid_query = {
        "MetricName": "ranged",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    # Positive control: the well-formed query succeeds and returns real data.
    result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[valid_query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and r["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert result["Status"] == "Complete", f"expected Complete, got {result['Status']!r}: {result}"
    assert abs(result["MetricValues"][0] - 4.0) < 1e-6, f"expected 4.0, got {result['MetricValues']!r}"

    # A malformed (non-ARN) ResourceArn fails the whole call, not just that query.
    invalid_query = dict(valid_query, ResourceArn="not-an-arn")
    code, message = _error(lambda: metrics.batch_get_metrics(MetricQueries=[valid_query, invalid_query]))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid SageMaker ARN", f"expected message 'Invalid SageMaker ARN', got {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name,
        Tags=[{"Key": "sim2real-behav", "Value": "batch-get-metrics-malformed-resource-arn-rejected"}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=name))
    return {"name": name, "arn": resp["TrialComponentArn"]}


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise TimeoutError(f"poll did not satisfy predicate within {timeout_s}s; last result: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
