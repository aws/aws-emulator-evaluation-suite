"""search-unknown-filter-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "search-unknown-filter-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sagemaker']

_TAG_KEY = "sim2realsuite"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll(fn, pred, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _create_experiment(ctx, name, nonce):
    sm = ctx.client("sagemaker")
    sm.create_experiment(
        ExperimentName=name,
        DisplayName=name,
        Tags=[{"Key": _TAG_KEY, "Value": nonce}],
    )
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=name))


def _search(ctx, expression):
    sm = ctx.client("sagemaker")
    resp = sm.search(
        Resource="Experiment", SearchExpression=expression, MaxResults=100
    )
    return sorted(
        r["Experiment"]["ExperimentName"] for r in resp.get("Results", [])
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Search refuses a filter on a property that does not exist, and on TrainingJobName for
    Resource=Experiment, with ValidationException "Unknown property name: <name>" rather than
    ignoring it, while the same expression on DisplayName narrows to the one expected experiment.
    """
    sm = ctx.client("sagemaker")
    nonce = ctx.unique_name("sim2real-behav-exp-")
    timeout_s = 300
    names = [f"{nonce}-alpha", f"{nonce}-beta"]
    for name in names:
        _create_experiment(ctx, name, nonce)

    tag_filter = {"Name": f"Tags.{_TAG_KEY}", "Operator": "Equals", "Value": nonce}
    baseline = _poll(
        lambda: _search(ctx, {"Operator": "And", "Filters": [tag_filter]}),
        lambda got: got == sorted(names),
        timeout_s=timeout_s,
    )
    assert baseline == sorted(names), (
        f"baseline tag search returned {baseline}, expected {sorted(names)}"
    )

    # Break exactly one thing: a property name that is not on the Experiment
    # SearchRecord shape. Search declares no errors in the Smithy model; real AWS
    # answers ValidationException "Unknown property name: <name>" for all three
    # variants below and for the cross-resource property case further down.
    # ("ExperimentNam" is the realistic near-miss typo; "Tags" is deliberately
    # NOT in this list -- Experiment.Tags is a documented searchable property.)
    for bad_name in ("NoSuchProperty", "ExperimentNam", "Metrics.accuracy"):
        code, message = _error(
            lambda: sm.search(
                Resource="Experiment",
                SearchExpression={
                    "Operator": "And",
                    "Filters": [
                        tag_filter,
                        {
                            "Name": bad_name,
                            "Operator": "Equals",
                            "Value": "anything",
                        },
                    ],
                },
                MaxResults=100,
            )
        )
        assert code == "ValidationException", (
            f"Search accepted an unknown filter property {bad_name!r} "
            f"(code={code!r}) -- filters that are silently dropped make every "
            f"Search answer a superset of the truth"
        )
        expected_message = f"Unknown property name: {bad_name}"
        assert message == expected_message, (
            f"rejection for {bad_name!r}: expected message {expected_message!r}, got {message!r}"
        )

    # A filter naming a valid property of the WRONG resource type must also be
    # refused, not ignored: TrainingJobName is not an Experiment property.
    code, message = _error(
        lambda: sm.search(
            Resource="Experiment",
            SearchExpression={
                "Operator": "And",
                "Filters": [
                    tag_filter,
                    {
                        "Name": "TrainingJobName",
                        "Operator": "Equals",
                        "Value": "anything",
                    },
                ],
            },
            MaxResults=100,
        )
    )
    assert code == "ValidationException", (
        f"Search accepted a cross-resource property (TrainingJobName on "
        f"Resource=Experiment), code={code!r}"
    )
    assert message == "Unknown property name: TrainingJobName", (
        f"expected message 'Unknown property name: TrainingJobName', got {message!r}"
    )

    # Effect absent / control: the valid expression still narrows correctly, so
    # the rejections above did not disturb the index or the fixtures.
    narrowed = _search(
        ctx,
        {
            "Operator": "And",
            "Filters": [
                tag_filter,
                {"Name": "DisplayName", "Operator": "Equals", "Value": names[0]},
            ],
        },
    )
    assert narrowed == [names[0]], (
        f"control search returned {narrowed}, expected [{names[0]}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
