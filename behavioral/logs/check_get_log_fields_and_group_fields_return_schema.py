"""get-log-fields-and-group-fields-return-schema."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "get-log-fields-and-group-fields-return-schema"
GROUP = "state-machine"
SERVICES = ["logs"]


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogGroupFields discovers a log group's ingested JSON fields; GetLogFields does not.

    For an unrecognized dataSourceType, GetLogFields returns the same generic fallback schema
    regardless of dataSourceName or log-group tags.
    """

    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-logs-fields-")
    log_stream_name = ctx.unique_name("sim2real-logs-fields-stream-")
    marker = uuid.uuid4().hex[:12]
    data_source_type = f"Custom-{marker}"

    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    logs.tag_log_group(
        logGroupName=log_group_name,
        tags={"cw:datasource:name": marker, "cw:datasource:type": data_source_type},
    )
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)

    now_ms = int(time.time() * 1000)
    for i in range(5):
        payload = json.dumps({"level": "INFO", "requestId": f"{marker}-{i}", "durationMs": 10 + i})
        logs.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[{"timestamp": now_ms + i, "message": payload}],
        )

    group_fields = _poll_until(
        lambda: {
            f["name"]: f["percent"]
            for f in logs.get_log_group_fields(
                logGroupName=log_group_name, time=int(time.time())
            )["logGroupFields"]
        },
        lambda fields: {"level", "requestId", "durationMs"}.issubset(fields.keys()),
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert group_fields is not None and {"level", "requestId", "durationMs"}.issubset(
        group_fields.keys()
    ), f"expected level/requestId/durationMs discovered by GetLogGroupFields, got {group_fields}"
    assert group_fields["level"] == 100
    assert group_fields["requestId"] == 100
    assert group_fields["durationMs"] == 100

    def _get_log_fields(data_source_name, source_type):
        try:
            resp = logs.get_log_fields(dataSourceName=data_source_name, dataSourceType=source_type)
            return {f["logFieldName"]: True for f in resp["logFields"]}
        except logs.exceptions.ResourceNotFoundException:
            return None

    tagged_fields = _poll_until(
        lambda: _get_log_fields(marker, data_source_type),
        lambda fields: fields is not None,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert tagged_fields is not None, (
        "GetLogFields raised ResourceNotFoundException for a never-before-seen "
        f"dataSourceType ({data_source_type!r}); expected a 200 with the generic fallback schema"
    )

    control_name = ctx.unique_name("sim2real-logs-fields-control-")
    control_type = f"Custom-{uuid.uuid4().hex[:12]}"
    control_fields = _get_log_fields(control_name, control_type)
    assert control_fields is not None, (
        "GetLogFields raised ResourceNotFoundException for an unrelated, wholly unregistered "
        f"dataSourceType ({control_type!r})"
    )

    assert tagged_fields == control_fields, (
        "GetLogFields returned a DIFFERENT field set for a data source whose owning log group is "
        f"tagged cw:datasource:name/type ({tagged_fields!r}) than for an unrelated, never-tagged, "
        f"never-referenced name/type pair ({control_fields!r}); expected the two to be identical, "
        "since GetLogFields' schema is a fixed function of dataSourceType and never samples the "
        "named data source's actual content or tags"
    )
    assert {"level", "requestId", "durationMs"}.isdisjoint(tagged_fields), (
        f"GetLogFields returned the log group's real ingested field names within {tagged_fields!r} "
        "for a dataSourceType AWS does not itself recognize; expected only the generic fallback "
        "schema -- if AWS has started sampling real content here, this check's premise is stale"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
