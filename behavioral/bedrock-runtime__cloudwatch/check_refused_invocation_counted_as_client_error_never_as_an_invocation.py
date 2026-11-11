"""refused-invocation-counted-as-client-error-never-as-an-invocation."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "refused-invocation-counted-as-client-error-never-as-an-invocation"
GROUP = "observability"
SERVICES = ["bedrock-runtime", "cloudwatch"]

# The refused id cannot succeed by its bare id, so any Invocations datapoint under it comes from
# refusals. Counts are floors: the account's AWS/Bedrock series are shared with other callers.
_OK_MODEL = "amazon.nova-lite-v1:0"
_REFUSED_MODEL = "amazon.nova-micro-v1:0"        # bare id: reachable only via an inference profile
_PROFILE_ID = "us.amazon.nova-micro-v1:0"        # the same model, named the way that works

_NAMESPACE = "AWS/Bedrock"
_DIMENSION = "ModelId"
_PERIOD_S = 60
_REFUSALS = 3
_CONVERGE_TIMEOUT_S = 210.0
_POLL_S = 15.0
_UNIT_COUNT = "Count"

_PROMPT = "Reply with exactly the single word PONG and nothing else."
_INFERENCE = {"maxTokens": 32, "temperature": 0.0}


def _statistics(cw, metric_name, model_id, start, end):
    return cw.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=[{"Name": _DIMENSION, "Value": model_id}],
        StartTime=start,
        EndTime=end,
        Period=_PERIOD_S,
        Statistics=["Sum"],
    )["Datapoints"]


def _sum(points) -> float:
    return sum(p["Sum"] for p in points)


def _error(fn, what):
    """Return (code, message), or RAISE if the call unexpectedly succeeded."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(
        f"{what} was expected to be refused but SUCCEEDED, which is an over-permissiveness "
        f"finding and also destroys this check's structural premise (H2); response={resp!r}"
    )


def _text(resp) -> str:
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


# timing:real-time — metric: 45 s https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html
@tags("axis:rejection", "cap:c3", "concern:metrics", "concern:negative-classes", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A refused Converse call is double-counted: InvocationClientErrors AND Invocations both rise.

    A successful call to another model is the positive control; ListMetrics confirms both series.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html
    """
    rt = ctx.client("bedrock-runtime")
    cw = ctx.client("cloudwatch")
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    window_start = (datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(seconds=_PERIOD_S))

    def now():
        return datetime.datetime.now(datetime.timezone.utc)

    error_baseline = _sum(
        _statistics(cw, "InvocationClientErrors", _REFUSED_MODEL, window_start, now()))
    ok_baseline = _sum(_statistics(cw, "Invocations", _OK_MODEL, window_start, now()))
    refused_inv_baseline = _sum(_statistics(cw, "Invocations", _REFUSED_MODEL, window_start, now()))

    # Positive control: a different model is invocable, so a fully-denied account cannot pass.
    ok = rt.converse(modelId=_OK_MODEL, messages=messages, inferenceConfig=_INFERENCE)
    assert ok["stopReason"] == "end_turn" and "PONG" in _text(ok).upper(), (
        f"the positive control against {_OK_MODEL!r} must be a real generation, else every "
        f"assertion below is explained by a broken account rather than by metric classification; "
        f"stopReason={ok['stopReason']!r} text={_text(ok)!r}"
    )

    # _PROFILE_ID is deliberately not invoked: if inference-profile traffic is attributed to the
    # underlying model id, it would add Invocations datapoints under _REFUSED_MODEL.

    for index in range(_REFUSALS):
        code, message = _error(
            lambda: rt.converse(modelId=_REFUSED_MODEL, messages=messages,
                                inferenceConfig=_INFERENCE),
            f"refusal {index} against the bare id {_REFUSED_MODEL!r}",
        )
        assert code == "ValidationException", (
            f"refusal {index}: a bare model id reachable only through an inference profile must be "
            f"refused with ValidationException; got {code!r} message={message!r}"
        )
        assert message == "Invocation of model ID amazon.nova-micro-v1:0 with on-demand throughput isn’t supported. Retry your request with the ID or ARN of an inference profile that contains this model.", (
            f"expected the exact ValidationException message AWS returns, got {message!r}"
        )
        assert "inference profile" in message.lower(), (
            f"refusal {index}: the message must name the inference-profile remedy, so this is the "
            f"routing refusal the check intends and not a permissions or lookup failure; got "
            f"{message!r}"
        )

    # Both metrics converge inside one deadline, so the wall clock is bounded by one timeout.
    deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    error_points: list[dict] = []
    ok_points: list[dict] = []
    refused_inv_points: list[dict] = []
    error_delta = 0.0
    ok_delta = 0.0
    refused_inv_delta = 0.0
    while time.monotonic() < deadline:
        error_points = _statistics(cw, "InvocationClientErrors", _REFUSED_MODEL,
                                   window_start, now())
        ok_points = _statistics(cw, "Invocations", _OK_MODEL, window_start, now())
        refused_inv_points = _statistics(cw, "Invocations", _REFUSED_MODEL, window_start, now())
        error_delta = _sum(error_points) - error_baseline
        ok_delta = _sum(ok_points) - ok_baseline
        refused_inv_delta = _sum(refused_inv_points) - refused_inv_baseline
        if error_delta >= _REFUSALS and ok_delta >= 1 and refused_inv_delta >= _REFUSALS:
            break
        time.sleep(_POLL_S)
    assert error_delta >= _REFUSALS, (
        f"{_REFUSALS} refused Converse calls against {_REFUSED_MODEL!r} must raise the AWS/Bedrock "
        f"InvocationClientErrors Sum for that {_DIMENSION} by at least {_REFUSALS} within "
        f"{_CONVERGE_TIMEOUT_S}s; baseline={error_baseline} observed delta={error_delta} "
        f"datapoints={error_points!r}"
    )
    units = sorted({p["Unit"] for p in error_points})
    assert units == [_UNIT_COUNT], (
        f"AWS/Bedrock InvocationClientErrors is documented with Unit {_UNIT_COUNT!r}; the "
        f"datapoints carried {units!r} ({error_points!r})"
    )
    # Asserted before the double-count so a target publishing no Invocations at all fails here.
    assert ok_delta >= 1, (
        f"the successful control against {_OK_MODEL!r} must raise its own Invocations Sum within "
        f"{_CONVERGE_TIMEOUT_S}s, else the double-count asserted below is explained by a target "
        f"that publishes no Invocations at all; baseline={ok_baseline} delta={ok_delta} "
        f"datapoints={ok_points!r}"
    )

    # The refusal is also counted as an Invocation; a floor, since only refusals can land here.
    assert refused_inv_delta >= _REFUSALS, (
        f"a ValidationException refusing the bare id {_REFUSED_MODEL!r} was measured on real AWS to "
        f"ALSO raise AWS/Bedrock Invocations for that {_DIMENSION}, by the same count as "
        f"InvocationClientErrors — not instead of it. {_REFUSALS} refused calls must raise the "
        f"Invocations Sum for {_REFUSED_MODEL!r} by at least {_REFUSALS} within "
        f"{_CONVERGE_TIMEOUT_S}s, in the same window InvocationClientErrors rose by {error_delta}; "
        f"baseline={refused_inv_baseline} observed delta={refused_inv_delta} "
        f"datapoints={refused_inv_points!r}"
    )
    refused_inv_units = sorted({p["Unit"] for p in refused_inv_points})
    assert refused_inv_units == [_UNIT_COUNT], (
        f"AWS/Bedrock Invocations is documented with Unit {_UNIT_COUNT!r}; the refused-model "
        f"datapoints carried {refused_inv_units!r} ({refused_inv_points!r})"
    )

    # An independent read through a different CloudWatch operation.
    dimension_sets: list[list[dict]] = []
    for page in cw.get_paginator("list_metrics").paginate(
            Namespace=_NAMESPACE, MetricName="Invocations"):
        for metric in page["Metrics"]:
            dimension_sets.append(metric["Dimensions"])
    assert [{"Name": _DIMENSION, "Value": _OK_MODEL}] in dimension_sets, (
        f"ListMetrics must surface an AWS/Bedrock Invocations series for the model that was "
        f"successfully invoked ({_OK_MODEL!r}); the dimension sets returned were "
        f"{dimension_sets!r}"
    )
    assert [{"Name": _DIMENSION, "Value": _REFUSED_MODEL}] in dimension_sets, (
        f"GetMetricStatistics already showed an Invocations datapoint for {_REFUSED_MODEL!r}, so "
        f"ListMetrics — a different operation, read independently — must surface that series too; "
        f"the dimension sets returned were {dimension_sets!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
