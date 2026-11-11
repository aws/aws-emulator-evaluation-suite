"""obs-opensearch-1-forged-domain-metric-in-aws-es-namespace-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-opensearch-1-forged-domain-metric-in-aws-es-namespace-rejected"
GROUP = 'metrics'
SERVICES = ['cloudwatch', 'opensearch']

POLL_DEADLINE_S = 180
POLL_STEP_S = 2


class _NoError(Exception):
    """Raised when a call expected to fail succeeded — never confusable with an error code."""


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise _NoError("the call succeeded; an error was expected")


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _values(cw, namespace: str, dims: list[dict], metric: str, start) -> list[float]:
    out: list[float] = []
    token = None
    while True:
        kw = dict(
            MetricDataQueries=[{
                "Id": "m0",
                "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": metric,
                                          "Dimensions": dims},
                               "Period": 60, "Stat": "Maximum"},
                "ReturnData": True,
            }],
            StartTime=start, EndTime=_now() + datetime.timedelta(minutes=2),
        )
        if token:
            kw["NextToken"] = token
        resp = cw.get_metric_data(**kw)
        for res in resp["MetricDataResults"]:
            out.extend(res["Values"])
        token = resp.get("NextToken")
        if not token:
            return out


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """PutMetricData into AWS/ES under a domain's ClientId and DomainName fails with the exact
    error and the datum is absent from that series and from ListMetrics, while the same datum in a
    custom namespace reads back."""
    cw = ctx.client("cloudwatch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain_name = ctx.unique_name("sim2real-xsvc-forge-")[:28].rstrip("-")
    dims = [{"Name": "ClientId", "Value": account_id},
            {"Name": "DomainName", "Value": domain_name}]
    datum = {"MetricName": "ClusterStatus.red", "Dimensions": dims, "Value": 1.0, "Unit": "Count"}
    start = _now() - datetime.timedelta(minutes=5)

    # Break exactly one thing: the namespace is the service-owned AWS/ES.
    try:
        err = _error(lambda: cw.put_metric_data(Namespace="AWS/ES", MetricData=[datum]))
    except _NoError:
        raise AssertionError(
            "PutMetricData into the reserved AWS/ES namespace was ACCEPTED; real AWS rejects it "
            "with InvalidParameterValue"
        ) from None
    expected = ("InvalidParameterValue", "The value AWS/ for parameter Namespace is invalid.")
    assert err == expected, f"PutMetricData into AWS/ES failed with {err!r}, expected {expected!r}"

    # Positive control: the identical datum in a customer namespace is accepted and readable.
    control_ns = f"Sim2Real/{domain_name}"
    cw.put_metric_data(Namespace=control_ns, MetricData=[datum])
    deadline = time.monotonic() + POLL_DEADLINE_S
    control = _values(cw, control_ns, dims, "ClusterStatus.red", start)
    while not control and time.monotonic() < deadline:
        time.sleep(POLL_STEP_S)
        control = _values(cw, control_ns, dims, "ClusterStatus.red", start)
    assert control == [1.0], (
        f"control datum in {control_ns!r} read back as {control!r} within {POLL_DEADLINE_S}s, "
        f"expected [1.0]"
    )

    # Effect absent: the control has become readable, so a forged AWS/ES datum, had it been
    # stored, would be too. Neither the series nor the catalogue holds one.
    forged = _values(cw, "AWS/ES", dims, "ClusterStatus.red", start)
    assert forged == [], f"AWS/ES holds datapoints for a domain nobody created: {forged!r}"
    listed = []
    for page in cw.get_paginator("list_metrics").paginate(
            Namespace="AWS/ES", Dimensions=[{"Name": "DomainName", "Value": domain_name}]):
        listed.extend(page["Metrics"])
    assert listed == [], (
        f"ListMetrics(AWS/ES, DomainName={domain_name}) lists forged metrics: "
        f"{[m['MetricName'] for m in listed]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
