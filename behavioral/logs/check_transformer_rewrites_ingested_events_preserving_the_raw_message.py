"""transformer-rewrites-ingested-events-preserving-the-raw-message."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "transformer-rewrites-ingested-events-preserving-the-raw-message"
GROUP = 'transformers'
SERVICES = ['logs']

_ORIGINAL_KEY = "orig"
_RENAMED_KEY = "renamed_field"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A renameKeys transformer rewrites ingested events as seen by GetLogRecord while @message and
    FilterLogEvents keep the raw bytes; an identical group without a transformer stays unrewritten.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Transformation.html
    """
    svc = ctx.client("logs")

    transformed = ctx.unique_name("sim2real-behav-lg-xform-")
    control = ctx.unique_name("sim2real-behav-lg-xformctl-")
    stream = ctx.unique_name("sim2real-behav-stream-")

    svc.create_log_group(logGroupName=transformed, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=transformed: svc.delete_log_group(logGroupName=_n))
    svc.create_log_group(logGroupName=control, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=control: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=transformed, logStreamName=stream)
    svc.create_log_stream(logGroupName=control, logStreamName=stream)

    marker = ctx.unique_name("sim2real-xformrun-")
    payload = {_ORIGINAL_KEY: marker}
    written = json.dumps(payload)

    # --- Install the transformer on ONE of the two groups: parse the JSON body, then
    # MOVE one key. The control group is configured identically in every other respect.
    svc.put_transformer(
        logGroupIdentifier=transformed,
        transformerConfig=[
            {"parseJSON": {}},
            {"renameKeys": {"entries": [{"key": _ORIGINAL_KEY, "renameTo": _RENAMED_KEY}]}},
        ],
    )
    ctx.on_cleanup(lambda _n=transformed: svc.delete_transformer(logGroupIdentifier=_n))

    installed = _poll_until(
        lambda: svc.get_transformer(logGroupIdentifier=transformed).get("transformerConfig"),
        lambda cfg: bool(cfg) and any("renameKeys" in p for p in cfg),
        timeout_s=60,
        interval_s=2.0,
        description="GetTransformer echoes the configured processor chain",
    )
    assert any("renameKeys" in p for p in installed), (
        f"GetTransformer returned {installed!r}, which does not contain the renameKeys processor "
        "this check installed -- every assertion below would be meaningless"
    )

    # The byte-identical event into both groups.
    for group in (transformed, control):
        resp = svc.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[{"timestamp": _now_ms(), "message": written}],
        )
        assert "rejectedLogEventsInfo" not in resp, (
            f"the event was partially rejected on {group!r}, so there is nothing to compare: "
            f"{resp!r}"
        )

    query_start_sec = int(time.time()) - 600

    def _records():
        """The two events as Insights sees them, keyed by their log group.

        One query spans both groups; ``@log`` is ``<account>:<logGroupName>``, which tells
        the deliberately identical messages apart."""
        query_id = svc.start_query(
            logGroupIdentifiers=[transformed, control],
            startTime=query_start_sec,
            endTime=int(time.time()) + 120,
            queryString=f"fields @ptr, @log | filter @message like /{marker}/ | limit 20",
        )["queryId"]
        deadline = time.monotonic() + 45
        rows = []
        while time.monotonic() < deadline:
            resp = svc.get_query_results(queryId=query_id)
            if resp["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                assert resp["status"] == "Complete", (
                    f"the Insights query used to reach GetLogRecord ended {resp['status']!r}, so "
                    f"neither event could be inspected: {resp!r}"
                )
                rows = resp.get("results", [])
                break
            time.sleep(2.0)
        out = {}
        for row_fields in rows:
            row = {f["field"]: f["value"] for f in row_fields}
            record = svc.get_log_record(logRecordPointer=row["@ptr"])["logRecord"]
            for group in (transformed, control):
                if row.get("@log", "").endswith(f":{group}"):
                    out[group] = record
        return out

    # Insights indexing of a fresh log group lags ingestion by about a minute, so the poll
    # keys on both records becoming queryable.
    records = _poll_until(
        _records,
        lambda recs: transformed in recs and control in recs,
        timeout_s=240,
        interval_s=15.0,
        description="the record from each of the two groups becomes queryable",
    )
    xform_record = records[transformed]
    control_record = records[control]

    # --- 1. The transformer really rewrote the event.
    assert _RENAMED_KEY in xform_record, (
        "the transformer was installed and echoed by GetTransformer, but the ingested event has no "
        f"{_RENAMED_KEY!r} field: {xform_record!r}"
    )
    assert xform_record[_RENAMED_KEY] == marker, (
        f"the transformer ran but {_RENAMED_KEY!r} holds {xform_record[_RENAMED_KEY]!r}; renameKeys "
        f"MOVES the value, so it must carry the original {marker!r}"
    )
    assert _ORIGINAL_KEY not in xform_record, (
        f"renameKeys must remove the old key, not duplicate it: {xform_record!r} still carries "
        f"{_ORIGINAL_KEY!r} -- copyValue, not renameKeys, is the processor that leaves both"
    )

    # --- 2. The raw bytes survive: the rewrite ADDS a representation of the customer's
    # payload, it does not replace it.
    assert xform_record.get("@message") == written, (
        "a transformer must not rewrite the stored raw event: @message on the transformed record is "
        f"{xform_record.get('@message')!r}, expected the bytes as written {written!r}"
    )

    def _stored_messages(group):
        messages: list[str] = []
        token = None
        while True:
            kwargs = {"logGroupName": group}
            if token is not None:
                kwargs["nextToken"] = token
            page = svc.filter_log_events(**kwargs)
            messages.extend(e["message"] for e in page.get("events", []))
            token = page.get("nextToken")
            if not token:
                break
        return messages

    # FilterLogEvents does not expose the transformed representation; it returns the raw bytes.
    xform_stored = _stored_messages(transformed)
    assert xform_stored == [written], (
        "FilterLogEvents on the transformed group must return the event with its original bytes -- "
        f"the transform is an added representation, not a substitution; got {xform_stored!r}, "
        f"expected {[written]!r}"
    )

    # --- 3. Control: the group with no transformer stores the identical event
    # unrewritten, so the transformer is provably the only discriminator.
    assert _RENAMED_KEY not in control_record, (
        "control: a log group with NO transformer must not produce the transformed field -- its "
        f"presence here means the rewrite is unconditional; got {control_record!r}"
    )
    assert control_record.get(_ORIGINAL_KEY) == marker, (
        "control: the untransformed record must still expose the ORIGINAL key, so the difference "
        f"between the two groups is the rename and not merely the absence of parsed fields; got "
        f"{control_record!r}"
    )
    assert control_record.get("@message") == written, (
        f"control: @message must be identical to what was written; got "
        f"{control_record.get('@message')!r} for {written!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
