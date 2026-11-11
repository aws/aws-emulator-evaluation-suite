"""describe-field-indexes-reflects-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-field-indexes-reflects-policy"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a field-index policy indexes a field and matching events are ingested,
    DescribeFieldIndexes(indexCategories=["CUSTOM"]) eventually reports it for the log group."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    log_stream_name = ctx.unique_name("sim2real-behav-ls-")
    field_name = "RequestId"

    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    ctx.on_cleanup(
        lambda: _ignore_notfound(lambda: logs.delete_index_policy(logGroupIdentifier=log_group_name))
    )
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)

    now_ms = int(time.time() * 1000)
    events = [
        {
            "timestamp": now_ms + i,
            "message": json.dumps({field_name: f"req-{i}", "level": "INFO", "text": "hello"}),
        }
        for i in range(5)
    ]
    logs.put_log_events(logGroupName=log_group_name, logStreamName=log_stream_name, logEvents=events)

    policy_document = json.dumps({"Fields": [field_name]})
    logs.put_index_policy(logGroupIdentifier=log_group_name, policyDocument=policy_document)

    found = _poll_until(
        lambda: logs.describe_field_indexes(
            logGroupIdentifiers=[log_group_name], indexCategories=["CUSTOM"]
        )["fieldIndexes"],
        lambda indexes: any(idx.get("fieldIndexName") == field_name for idx in indexes),
        timeout_s=150.0,
        interval_s=10.0,
    )
    if found is None:
        raise AssertionError(
            f"CUSTOM field index '{field_name}' was not discovered by DescribeFieldIndexes within "
            "the poll window (async index-scan latency); real AWS scans periodically and this can "
            "take longer than a standard check budget"
        )
    matching = [idx for idx in found if idx.get("fieldIndexName") == field_name]
    assert matching, f"expected field index {field_name} in {found}"
    assert matching[0]["indexCategory"] == "CUSTOM", f"unexpected indexCategory: {matching[0]}"
    assert log_group_name in matching[0].get("logGroupIdentifier", ""), (
        f"expected logGroupIdentifier to reference {log_group_name}, got {matching[0]}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return None


def _ignore_notfound(fn) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        code = resp.get("Error", {}).get("Code") if isinstance(resp, dict) else None
        if code not in ("ResourceNotFoundException", None):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
