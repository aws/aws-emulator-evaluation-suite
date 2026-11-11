"""field-index-policy-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "field-index-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIndexPolicy creates an index policy visible via DescribeIndexPolicies
    and (eventually) reflected in DescribeFieldIndexes, removable via
    DeleteIndexPolicy."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-idxpol-")
    logs.create_log_group(
        logGroupName=log_group_name,
        logGroupClass="STANDARD",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    policy_document = json.dumps(
        {"FieldsV2": {"RequestId": {"type": "FIELD_INDEX"}, "Status": {"type": "FACET"}}}
    )
    put_resp = logs.put_index_policy(
        logGroupIdentifier=log_group_name, policyDocument=policy_document
    )
    assert put_resp["indexPolicy"]["logGroupIdentifier"] in (log_group_name,) or (
        log_group_name in put_resp["indexPolicy"]["logGroupIdentifier"]
    )
    assert put_resp["indexPolicy"]["policyDocument"] == policy_document

    described = logs.describe_index_policies(logGroupIdentifiers=[log_group_name])
    policies = described["indexPolicies"]
    assert len(policies) == 1, f"expected exactly one index policy, got {policies}"
    assert policies[0]["policyDocument"] == policy_document
    assert policies[0]["source"] == "LOG_GROUP", f"expected source LOG_GROUP, got {policies[0]}"

    # Ingest matching data and give the service a chance to build the custom
    # field index; this is eventually-consistent, so poll with a bounded
    # window and fail if the index never appears.
    log_stream_name = ctx.unique_name("stream-")
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        logEvents=[
            {"timestamp": now_ms, "message": json.dumps({"RequestId": "abc-123", "Status": "OK"})}
        ],
    )

    def _has_custom_index():
        resp = logs.describe_field_indexes(
            logGroupIdentifiers=[log_group_name], indexCategories=["CUSTOM"]
        )
        return resp["fieldIndexes"]

    found = _poll_until(_has_custom_index, lambda v: bool(v), timeout_s=150.0, interval_s=10.0)
    if not found:
        raise AssertionError(
            f"no CUSTOM field index discovered for {log_group_name} within the poll window; "
            f"put_index_policy set policyDocument={policy_document}"
        )
    names = {idx.get("fieldIndexName") for idx in found}
    assert "RequestId" in names, f"expected 'RequestId' among CUSTOM field indexes, got {found}"
    request_id_index = next(idx for idx in found if idx.get("fieldIndexName") == "RequestId")
    assert request_id_index["indexCategory"] == "CUSTOM", (
        f"expected indexCategory CUSTOM, got {request_id_index}"
    )
    assert log_group_name in request_id_index.get("logGroupIdentifier", ""), (
        f"expected logGroupIdentifier to reference {log_group_name}, got {request_id_index}"
    )

    logs.delete_index_policy(logGroupIdentifier=log_group_name)

    try:
        described_after = logs.describe_index_policies(logGroupIdentifiers=[log_group_name])
        remaining = described_after["indexPolicies"]
    except logs.exceptions.ResourceNotFoundException:
        remaining = []
    assert remaining == [], f"index policy still present after delete: {remaining}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
