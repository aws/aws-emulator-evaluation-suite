"""bedrock-invocation-publishes-token-metrics-to-cloudwatch."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "bedrock-invocation-publishes-token-metrics-to-cloudwatch"
GROUP = "observability"
SERVICES = ["bedrock", "cloudwatch"]

MODEL_ID = "amazon.nova-lite-v1:0"
_NAMESPACE = "AWS/Bedrock"
_PERIOD_S = 60
_CONVERGE_TIMEOUT_S = 180.0
_LIST_TIMEOUT_S = 90.0  # ListMetrics lags GetMetricStatistics on real AWS
_POLL_S = 15.0


def _sum_over(cw, metric_name, model_id, start, end):
    """(Sum of every datapoint, the datapoint list) for one metric at one ModelId dimension."""
    resp = cw.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=[{"Name": "ModelId", "Value": model_id}],
        StartTime=start,
        EndTime=end,
        Period=_PERIOD_S,
        Statistics=["Sum"],
    )
    points = resp["Datapoints"]
    return sum(p["Sum"] for p in points), points


def _converse(rt, prompt, max_tokens):
    """One short, cheap inference. Returns the API's own inline usage report."""
    response = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": max_tokens, "temperature": 0.0},
    )
    usage = response["usage"]
    assert usage["inputTokens"] > 0 and usage["outputTokens"] > 0, (
        f"the inference must report non-zero token usage for this check to have a floor to assert; "
        f"usage={usage!r}"
    )
    return usage


# timing:real-time — metric: 15 s https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html
@tags("axis:happy-path", "concern:metrics", "dp:api", "plane:data", "cap:c3", "timing:real-time")
def run(ctx) -> None:
    """AWS/Bedrock InputTokenCount/OutputTokenCount on the ModelId dimension account for at least
    the tokens two Converse calls reported inline, inside the check's window, and ListMetrics shows
    the series; a never-invoked ModelId has no datapoints.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")
    cw = ctx.client("cloudwatch")

    details = bc.get_foundation_model(modelIdentifier=MODEL_ID)["modelDetails"]
    dimension_model = details["modelId"]
    assert dimension_model == MODEL_ID, (
        f"GetFoundationModel must echo the modelIdentifier that is about to be invoked and used as "
        f"the ModelId metric dimension; asked for {MODEL_ID!r}, catalog reported "
        f"{dimension_model!r}"
    )

    # Start one period early: Bedrock aggregates on a 1-minute boundary and the call may land in the preceding minute.
    opened_at = datetime.now(timezone.utc)
    start = (opened_at - timedelta(seconds=_PERIOD_S)).replace(microsecond=0)

    usage_one = _converse(rt, "Name three colours, comma separated, nothing else.", 40)
    usage_two = _converse(rt, "Name three fruits, comma separated, nothing else.", 40)
    want_input = usage_one["inputTokens"] + usage_two["inputTokens"]
    want_output = usage_one["outputTokens"] + usage_two["outputTokens"]

    # The series is account-wide and shared, so the assertion is a token floor, not an exact delta.
    deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    got_input, input_points = 0.0, []
    while True:
        end = datetime.now(timezone.utc) + timedelta(seconds=_PERIOD_S)
        got_input, input_points = _sum_over(cw, "InputTokenCount", MODEL_ID, start, end)
        if got_input >= want_input:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{_NAMESPACE} InputTokenCount at ModelId={MODEL_ID!r} accounted for only "
                f"{got_input} tokens within {_CONVERGE_TIMEOUT_S}s, but the two inferences reported "
                f"{want_input} input tokens inline (usage {usage_one!r} and {usage_two!r}); "
                f"datapoints={input_points!r}"
            )
        time.sleep(_POLL_S)

    end = datetime.now(timezone.utc) + timedelta(seconds=_PERIOD_S)
    got_output, output_points = _sum_over(cw, "OutputTokenCount", MODEL_ID, start, end)
    assert got_output >= want_output, (
        f"{_NAMESPACE} OutputTokenCount at ModelId={MODEL_ID!r} accounted for only {got_output} "
        f"tokens, but the two inferences reported {want_output} output tokens inline; "
        f"datapoints={output_points!r}"
    )

    for point in input_points:
        assert start <= point["Timestamp"] <= end, (
            f"InputTokenCount datapoint at {point['Timestamp']!r} lies outside the window "
            f"[{start!r}, {end!r}] this check opened; datapoints={input_points!r}"
        )

    absent_model = f"sim2real.nonexistent-{uuid.uuid4().hex[:12]}-v1:0"
    absent_sum, absent_points = _sum_over(cw, "InputTokenCount", absent_model, start, end)
    assert absent_points == [], (
        f"InputTokenCount must be dimensioned on ModelId, so a model id that was never invoked "
        f"({absent_model!r}) must have no datapoints; got {absent_points!r} summing to {absent_sum}"
    )

    list_deadline = time.monotonic() + _LIST_TIMEOUT_S
    seen_dimensions = []
    while True:
        seen_dimensions = []
        for page in cw.get_paginator("list_metrics").paginate(
            Namespace=_NAMESPACE, MetricName="InputTokenCount"
        ):
            for metric in page["Metrics"]:
                seen_dimensions.append(metric["Dimensions"])
        if [{"Name": "ModelId", "Value": MODEL_ID}] in seen_dimensions:
            break
        if time.monotonic() >= list_deadline:
            raise AssertionError(
                f"ListMetrics did not surface {_NAMESPACE} InputTokenCount dimensioned on exactly "
                f"[ModelId={MODEL_ID!r}] within {_LIST_TIMEOUT_S}s even though GetMetricStatistics "
                f"already reported {got_input} tokens for it; dimension sets seen: "
                f"{seen_dimensions!r}"
            )
        time.sleep(_POLL_S)

    assert [{"Name": "ModelId", "Value": absent_model}] not in seen_dimensions, (
        f"ListMetrics surfaced a series for the never-invoked model {absent_model!r}; dimension "
        f"sets seen: {seen_dimensions!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
