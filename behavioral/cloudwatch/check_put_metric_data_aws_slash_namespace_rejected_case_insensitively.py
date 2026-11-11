"""put-metric-data-aws-slash-namespace-rejected-case-insensitively."""
from __future__ import annotations

# The Smithy model declares Namespace as length 1..255, pattern '^[^:]', and only DOCUMENTS that a
# caller "should not" begin with 'AWS/'. Real AWS behaves as follows:
#   'AWS/<x>', 'aws/<x>', 'Aws/<x>' -> 400 InvalidParameterValue
#                                      "The value AWS/ for parameter Namespace is invalid."
#   'AWS<x>' (no slash), 'AWS'      -> accepted
# so the service reserves the 'aws/' prefix case-insensitively, and the slash is what makes it
# reserved.

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-aws-slash-namespace-rejected-case-insensitively"
GROUP = "validation"
SERVICES = ["cloudwatch"]

_CEILING_S = 180.0


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """PutMetricData rejects any 'aws/' namespace regardless of case, and only with the slash.

    The same payload under 'AWS<u>' is accepted and readable, while no rejected namespace
    returns values for the series.
    """
    cw = ctx.client("cloudwatch")
    # The accepted control metric has no delete API and ages out after two weeks, so its
    # namespace and dimension value are unique per run.
    deadline = time.monotonic() + _CEILING_S
    token = ctx.unique_name("sim2realnsprobe")
    marker = ctx.unique_name("sim2real-ns-marker-")
    payload = [{"MetricName": "Probe", "Dimensions": [{"Name": "Run", "Value": marker}],
                "Value": 7.0, "Unit": "Count"}]

    def _error(fn) -> tuple[str, str, int]:
        try:
            fn()
        except ClientError as e:
            err = e.response["Error"]
            return err["Code"], err["Message"], e.response["ResponseMetadata"]["HTTPStatusCode"]
        raise AssertionError("call was ACCEPTED; real AWS rejects it")

    started = datetime.now(timezone.utc)
    rejected = [f"AWS/{token}", f"aws/{token}", f"Aws/{token}"]
    for ns in rejected:
        code, message, status = _error(lambda ns=ns: cw.put_metric_data(Namespace=ns, MetricData=payload))
        assert (code, status) == ("InvalidParameterValue", 400), (
            f"PutMetricData(Namespace={ns!r}) returned {code!r}/{status!r}, "
            f"expected 'InvalidParameterValue'/400 (reserved 'aws/' prefix)"
        )
        # The message names the reserved prefix in upper case whatever casing was sent.
        assert message == "The value AWS/ for parameter Namespace is invalid.", (
            f"PutMetricData(Namespace={ns!r}) message {message!r}"
        )

    accepted = f"AWS{token}"
    resp = cw.put_metric_data(Namespace=accepted, MetricData=payload)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"PutMetricData(Namespace={accepted!r}) returned {resp['ResponseMetadata']!r}"
    )

    def _q(i: int, ns: str) -> dict:
        return {"Id": f"q{i}", "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": ns, "MetricName": "Probe",
                       "Dimensions": [{"Name": "Run", "Value": marker}]},
            "Period": 60, "Stat": "Sum"}}

    namespaces = [accepted] + rejected
    queries = [_q(i, ns) for i, ns in enumerate(namespaces)]
    start = started.replace(second=0, microsecond=0) - timedelta(minutes=1)
    while True:
        res = {r["Id"]: r["Values"] for r in cw.get_metric_data(
            MetricDataQueries=queries, StartTime=start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        )["MetricDataResults"]}
        if res.get("q0"):
            break
        left = deadline - time.monotonic()
        assert left > 0, (
            f"{_CEILING_S:.0f}s ceiling exhausted: accepted put into {accepted!r} never readable"
        )
        time.sleep(min(5.0, left))

    assert res["q0"] == [7.0], f"accepted namespace {accepted!r} read back {res['q0']!r}"
    for i, ns in enumerate(namespaces[1:], start=1):
        assert res.get(f"q{i}") == [], (
            f"REJECTED namespace {ns!r} is readable anyway: {res.get(f'q{i}')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
