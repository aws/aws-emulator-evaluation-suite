"""obs-logs-2-transformer-without-leading-parser-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-logs-2-transformer-without-leading-parser-rejected"
GROUP = "metric-filters"
SERVICES = ["cloudwatch", "logs"]

_PATTERN = '{ $.sev = "HIGH" }'
_N_EVENTS = 3
_ADD_SEV = {"addKeys": {"entries": [{"key": "sev", "value": "HIGH"}]}}
# One shared ceiling for every asynchronous wait; real AWS publishes these within ~30 s.
_DEADLINE_S = 420.0


@tags("axis:rejection", "cap:c2", "concern:metrics", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """PutTransformer refuses a lone addKeys (no leading parser) and installs nothing, so the group's
    transformed-log filter stays empty while a valid sibling counts 3; after repair, new events count.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-xsvc-txrej-ns-")
    refused = ctx.unique_name("sim2real-xsvc-lg-txrej-")
    control = ctx.unique_name("sim2real-xsvc-lg-txctl-")
    stream = "events"

    for group, metric in ((refused, "Refused"), (control, "Control")):
        logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
        ctx.on_cleanup(lambda _g=group: logs.delete_log_group(logGroupName=_g))
        logs.create_log_stream(logGroupName=group, logStreamName=stream)
        logs.put_metric_filter(
            logGroupName=group, filterName="txrej", filterPattern=_PATTERN,
            applyOnTransformedLogs=True,
            metricTransformations=[
                {"metricName": metric, "metricNamespace": namespace, "metricValue": "1"}
            ],
        )
        ctx.on_cleanup(lambda _g=group: logs.delete_metric_filter(logGroupName=_g, filterName="txrej"))

    # Registered BEFORE the call: a target that wrongly accepts it has installed a transformer.
    # The model does not require a parser first, so a model-driven target may accept this.
    ctx.on_cleanup(lambda: logs.delete_transformer(logGroupIdentifier=refused))
    err = _error(lambda: logs.put_transformer(
        logGroupIdentifier=refused, transformerConfig=[_ADD_SEV]))
    expected = (
        "InvalidParameterException",
        "Transformer config should begin with parser. Allowed parsers are parsePostgres, parseWAF, "
        "parseCloudfront, parseCloudfrontOCSF, parseRoute53, parseLambda, parseVPC, parseSyslog, "
        "parseRDS, parseCiscoFTD, parseF5BigIP, parseCiscoISE, parseForescoutNac, parseInfobloxDDI, "
        "parseToOCSF, parseJSON, grok, csv, parseKeyValue",
    )
    assert err == expected, (
        "PutTransformer whose first processor is addKeys (not a parser) must be refused: "
        f"got {err!r}, expected {expected!r}"
    )
    after_refusal = logs.get_transformer(logGroupIdentifier=refused).get("transformerConfig")
    assert after_refusal == [], (
        f"the refused transformer must not be installed; GetTransformer returned {after_refusal!r}"
    )

    logs.put_transformer(logGroupIdentifier=control, transformerConfig=[{"parseJSON": {}}, _ADD_SEV])
    ctx.on_cleanup(lambda: logs.delete_transformer(logGroupIdentifier=control))
    control_kinds = [next(iter(p)) for p in
                     logs.get_transformer(logGroupIdentifier=control).get("transformerConfig") or []]
    assert control_kinds == ["parseJSON", "addKeys"], (
        f"the control transformer must be installed as parseJSON->addKeys; got {control_kinds!r}"
    )

    write_ms = int(time.time() * 1000)
    start = (datetime.fromtimestamp(write_ms / 1000, timezone.utc)
             .replace(second=0, microsecond=0) - timedelta(minutes=2))
    deadline = time.monotonic() + _DEADLINE_S
    _write(logs, refused, stream, write_ms, "before-repair")
    _write(logs, control, stream, write_ms, "before-repair")

    def _points(metric):
        return cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, StartTime=start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60, Statistics=["Sum"],
        ).get("Datapoints", [])

    def _sum(points):
        return sum(p.get("Sum", 0.0) for p in points)

    control_pts = _poll_until(
        lambda: _points("Control"), lambda pts: _sum(pts) >= _N_EVENTS, deadline=deadline,
        description=f"{namespace}/Control to reach Sum {_N_EVENTS}",
    )
    assert _sum(control_pts) == float(_N_EVENTS), (
        f"the control group's transformed-log filter must count exactly {_N_EVENTS}; got {control_pts!r}"
    )
    # The control's arrival is the barrier, so an empty refused metric is not publication lag.
    refused_pts = _points("Refused")
    assert refused_pts == [], (
        "the refused group has no transformer, so its applyOnTransformedLogs filter must publish "
        f"nothing; after the control's datapoint arrived it holds {refused_pts!r}"
    )

    # Repair the one broken thing; only events ingested from now on are transformed.
    logs.put_transformer(logGroupIdentifier=refused, transformerConfig=[{"parseJSON": {}}, _ADD_SEV])
    repair_ms = int(time.time() * 1000)
    _write(logs, refused, stream, repair_ms, "after-repair")
    repaired = _poll_until(
        lambda: _points("Refused"), lambda pts: _sum(pts) >= _N_EVENTS, deadline=deadline,
        description=f"{namespace}/Refused to reach Sum {_N_EVENTS} after the repair",
    )
    assert _sum(repaired) == float(_N_EVENTS), (
        f"after the repair the filter must count exactly the {_N_EVENTS} newly ingested events "
        f"(not the {_N_EVENTS} ingested untransformed before it); got {repaired!r}"
    )


def _write(logs, group, stream, base_ms, phase):
    resp = logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": base_ms + i, "message": json.dumps({"phase": phase, "n": i})}
                   for i in range(_N_EVENTS)],
    )
    assert "rejectedLogEventsInfo" not in resp, f"the {phase} batch was partially rejected: {resp!r}"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the AWS error. An unexpected SUCCESS raises rather than returning."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, deadline, interval_s=5.0, description="condition"):
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {description}; last: {last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
