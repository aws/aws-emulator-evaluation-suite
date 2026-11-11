"""list-resource-evaluations-time-range-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resource-evaluations-time-range-ordering"
GROUP = "ordering"
SERVICES = ["config"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied, last observed value: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Three PROACTIVE StartResourceEvaluation calls each appear once in ListResourceEvaluations for their
    EvaluationContextIdentifier, a wide TimeWindow includes them and an earlier one excludes them, and an
    inverted TimeWindow fails with InvalidTimeRangeException and an empty message."""
    cfg = ctx.client("config")
    evaluation_context = ctx.unique_name("sim2real-evalctx-")

    def _evaluate(seq: int) -> str:
        bucket_name = ctx.unique_name(f"sim2real-widget-{seq}-")
        details = {
            "ResourceId": bucket_name,
            "ResourceType": "AWS::S3::Bucket",
            # Must conform to the AWS::S3::Bucket CloudFormation resource schema --
            # StartResourceEvaluation validates ResourceConfiguration against it.
            "ResourceConfiguration": json.dumps({"BucketName": bucket_name}),
        }
        resp = cfg.start_resource_evaluation(
            ResourceDetails=details,
            EvaluationMode="PROACTIVE",
            EvaluationContext={"EvaluationContextIdentifier": evaluation_context},
        )
        return resp["ResourceEvaluationId"]

    before_first = time.time()
    eval_ids = []
    for seq in range(3):
        eval_ids.append(_evaluate(seq))
        time.sleep(1.5)  # ensure distinct EvaluationStartTimestamp values
    after_last = time.time()

    def _list(extra_filters=None):
        filters = {"EvaluationContextIdentifier": evaluation_context}
        if extra_filters:
            filters.update(extra_filters)
        return cfg.list_resource_evaluations(Filters=filters, Limit=100)["ResourceEvaluations"]

    entries = _poll_until(_list, lambda items: len(items) >= 3, timeout_s=60, interval_s=3)
    ours = [e for e in entries if e["ResourceEvaluationId"] in eval_ids]
    # No evaluation lost, none duplicated.
    assert len(ours) == 3, f"expected 3 tracked evaluations, found {len(ours)}: {ours}"
    assert len({e["ResourceEvaluationId"] for e in ours}) == 3, f"duplicate entries returned: {ours}"

    # A TimeWindow spanning well before/after our three calls must still surface
    # all three -- the filter must not spuriously exclude in-range evaluations.
    wide_window = _list({"TimeWindow": {"StartTime": before_first - 60, "EndTime": after_last + 60}})
    wide_ids = {e["ResourceEvaluationId"] for e in wide_window}
    assert set(eval_ids) <= wide_ids, (
        f"TimeWindow covering the full evaluation span is missing evaluations: "
        f"expected {eval_ids} subset of {wide_ids}"
    )

    # A TimeWindow entirely *before* our first call must exclude all three --
    # the filter must not spuriously include out-of-range evaluations.
    empty_window = _list({"TimeWindow": {"StartTime": before_first - 3600, "EndTime": before_first - 1}})
    empty_ids = {e["ResourceEvaluationId"] for e in empty_window}
    assert not (set(eval_ids) & empty_ids), (
        f"TimeWindow entirely before our evaluations unexpectedly returned: {set(eval_ids) & empty_ids}"
    )

    # Negative: an inverted time window (StartTime chronologically after EndTime)
    # is rejected outright, and does not silently return an empty/garbled page.
    now = time.time()
    code, message = _error(
        lambda: cfg.list_resource_evaluations(
            Filters={"TimeWindow": {"StartTime": now, "EndTime": now - 3600}}
        )
    )
    assert code == "InvalidTimeRangeException", f"expected InvalidTimeRangeException, got {code!r}"
    # AWS sends this refusal with an empty message.
    assert message == "", f"expected an empty InvalidTimeRangeException message, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

