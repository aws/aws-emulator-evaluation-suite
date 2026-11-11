"""put-metric-data-invalid-unit-rejected."""
# An unmodelled metric Unit must be rejected, AND a datum published with a valid unit must be retrievable.
#
# The two halves are one defect and have to be asserted together, because each alone is passable for the
# wrong reason: a target that rejects every PutMetricData satisfies the negative, and one that accepts
# everything and stores nothing looks fine if you only read the 200.
#
# MEASURED: the service answers InvalidParameterValue -- not ValidationError -- and the message names the
# PARAMETER PATH plus the whole valid set; it never echoes the bad value. The enum is case-sensitive, so a
# correctly-spelled-but-wrong-case unit is also refused. botocore passes enum members through without
# client-side validation, so the request does reach the service and the negative grades something.
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-invalid-unit-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudwatch"]

VALID_UNIT = "Count"
BOGUS_UNIT = "Furlongs"
WRONG_CASE_UNIT = "count"          # the enum is case-sensitive: measured rejected
UNIT_PARAM_PATH = "MetricData.member.1.Unit"
# The permitted set exactly as the refusal lists it, in the service's own order.
UNIT_SET = (
    "Megabits, Terabits, Gigabits, Count, Bytes, Gigabytes, Gigabytes/Second, Kilobytes, "
    "Kilobits/Second, Terabytes, Terabits/Second, Bytes/Second, Percent, Megabytes, "
    "Megabits/Second, Milliseconds, Microseconds, Kilobytes/Second, Gigabits/Second, "
    "Megabytes/Second, Bits, Bits/Second, Count/Second, Seconds, Kilobits, Terabytes/Second, None"
)
UNIT_MESSAGE = f"The parameter {UNIT_PARAM_PATH} must be a value in the set [ {UNIT_SET} ]."
DATAPOINT_VALUE = 7.0
VISIBLE_TIMEOUT_S = 300.0


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unmodelled metric Unit is rejected, and the datum published with a VALID unit is actually
    retrievable -- so the rejection cannot be a target that refuses everything, and the acceptance
    cannot be a target that stores nothing."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real/behav/unit-")
    metric = "ProbeMetric"

    # --- Beat 1: the negative -- an unmodelled Unit is refused ------------------------------------
    # AWS answers InvalidParameterValue -- NOT ValidationError --
    # and the message names the PARAMETER PATH plus the whole valid set; it never echoes the bad value.
    # botocore passes enum members through without client-side validation, so the request does reach
    # the service and the negative grades something.
    for label, unit in (("unmodelled", BOGUS_UNIT), ("wrong-case", WRONG_CASE_UNIT)):
        error = _client_error(
            lambda u=unit: cw.put_metric_data(
                Namespace=namespace,
                MetricData=[{"MetricName": metric, "Value": DATAPOINT_VALUE, "Unit": u}],
            )
        )
        assert error.get("Code") == "InvalidParameterValue", (
            f"[{label}] Unit is a closed enum, so {unit!r} must be refused with "
            f"InvalidParameterValue; got {error.get('Code')!r}: {error.get('Message')!r}"
        )
        # The refusal names the parameter path and enumerates the permitted set: that shows the
        # validator knows the enum rather than refusing blindly.
        assert error.get("Message") == UNIT_MESSAGE, (
            f"[{label}] refusal message {error.get('Message')!r}"
        )

    # --- Beat 2: the positive control -- a VALID unit is accepted AND retrievable ------------------
    # Without this the negative passes against a target that rejects all metric writes. Retrievability
    # is the half that breaks independently: a metric accepted, then no Datapoints returned.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric, "Value": DATAPOINT_VALUE, "Unit": VALID_UNIT}],
    )
    # No cleanup registered: CloudWatch custom metrics cannot be deleted and expire on their own
    # retention schedule. Registering a no-op teardown would be worse than registering none.
    # _await_datapoints RAISES if nothing ever becomes retrievable, which IS the "accepted the write,
    # stored nothing" half of this defect -- so there is no bare truthiness assert here on purpose.
    datapoints = _await_datapoints(ctx, cw, namespace, metric)
    sums = [d["Sum"] for d in datapoints]
    assert any(abs(s - DATAPOINT_VALUE) < 0.001 for s in sums), (
        f"the retrieved datapoint must carry the value this run published ({DATAPOINT_VALUE}); got "
        f"sums {sums!r}"
    )
    units = {d.get("Unit") for d in datapoints}
    assert units == {VALID_UNIT}, (
        f"the stored datum must retain its unit {VALID_UNIT!r}, got {units!r}"
    )

    # --- Beat 3: the refused datum was never stored -----------------------------------------------
    # Effect-absent for the negative. Same namespace, so a target that accepted the bogus-unit write
    # would surface it here as a second, differently-united datapoint.
    bogus_units = {d.get("Unit") for d in _statistics(cw, namespace, metric)}
    assert BOGUS_UNIT not in bogus_units, (
        f"the rejected write must not have been stored; {namespace}/{metric} reports units "
        f"{bogus_units!r}"
    )


# ===== helpers =====


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING input real AWS refuses is the strongest signal available and must not be reduced to
    an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _statistics(cw, namespace: str, metric: str) -> list[dict]:
    """One GetMetricStatistics read over a window wide enough to contain a datum published seconds ago.

    The window starts 10 minutes back and ends 5 minutes ahead: CloudWatch timestamps a datum at the
    server's clock, and a window ending 'now' can exclude a datum whose timestamp is marginally ahead
    of the caller's clock.
    """
    now = time.time()
    return cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        StartTime=_iso(now - 600),
        EndTime=_iso(now + 300),
        Period=60,
        Statistics=["Sum"],
    )["Datapoints"]


def _await_datapoints(ctx, cw, namespace: str, metric: str) -> list[dict]:
    """Poll until the published datum is retrievable. RAISES on timeout rather than returning empty,
    so a timeout is never mistaken for 'the metric was not stored'."""
    left = ctx.time_left()
    deadline = time.monotonic() + (VISIBLE_TIMEOUT_S if left is None else min(VISIBLE_TIMEOUT_S, left))
    while time.monotonic() < deadline:
        points = _statistics(cw, namespace, metric)
        if points:
            return points
        time.sleep(2)
    raise AssertionError(
        f"no Datapoints for {namespace}/{metric} within {VISIBLE_TIMEOUT_S}s of publishing"
    )


def _iso(epoch: float):
    import datetime

    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
