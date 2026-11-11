"""search-and-batch-get-return-published-record."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-and-batch-get-return-published-record"
GROUP = "discovery"
SERVICES = ["agent-registry"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_registry(client, registry_id: str, until: str, *, budget_s: float = 180.0) -> dict:
    deadline = time.monotonic() + budget_s
    while True:
        got = client.get_registry(registryId=registry_id)
        if got["status"] == until:
            return got
        assert not got["status"].endswith("FAILED"), f"registry entered {got['status']!r}: {got}"
        assert time.monotonic() < deadline, f"registry stuck at {got['status']!r} after {budget_s}s"
        time.sleep(3)


def _wait_record(client, registry_id: str, record_id: str, until: str, *, budget_s: float = 120.0) -> dict:
    deadline = time.monotonic() + budget_s
    while True:
        got = client.get_registry_record(registryId=registry_id, recordId=record_id)
        if got["status"] == until:
            return got
        assert not got["status"].endswith("FAILED"), f"record entered {got['status']!r}: {got}"
        assert time.monotonic() < deadline, f"record stuck at {got['status']!r} after {budget_s}s"
        time.sleep(2)


def _wait_discoverable(search_fn, *, budget_s: float = 120.0) -> dict:
    """The first non-empty ``SearchDiscoverableRegistryRecords`` answer after approval."""
    deadline = time.monotonic() + budget_s
    while True:
        got = search_fn()
        if got["registryRecords"]:
            return got
        assert time.monotonic() < deadline, f"approved record never became searchable after {budget_s}s"
        time.sleep(2)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A registry record approved through the control plane is returned, with its name and
    descriptor types, by both SearchDiscoverableRegistryRecords and BatchGetDiscoverableRegistryRecord.
    """
    arc = ctx.client("agent-registry-control")
    ar = ctx.client("agent-registry")

    registry_name = ctx.unique_name("sim2real-behav-ar-reg-")
    registry = arc.create_registry(name=registry_name)
    registry_id = registry["registryArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(lambda: arc.delete_registry(registryId=registry_id), "ResourceNotFoundException"))
    _wait_registry(arc, registry_id, "READY")

    record_name = ctx.unique_name("sim2real-behav-ar-rec-")
    description = "Weather alert webhook integration for coastal monitoring stations"
    record = arc.create_registry_record(
        registryId=registry_id,
        name=record_name,
        description=description,
        recordType="CUSTOM",
        descriptors={"custom": {"data": json.dumps({"summary": description})}},
    )
    record_id = record["recordArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=registry_id, recordId=record_id),
        "ResourceNotFoundException",
    ))
    _wait_record(arc, registry_id, record_id, "DRAFT")

    submitted = arc.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)
    assert submitted["status"] == "PENDING_APPROVAL", (
        f"expected the submission to leave the record PENDING_APPROVAL, got {submitted['status']!r}"
    )

    approved = arc.update_registry_record_status(
        registryId=registry_id, recordId=record_id, status="APPROVED",
        statusReason="sim2real behavioral approval",
    )
    assert approved["status"] == "APPROVED", f"expected APPROVED, got {approved['status']!r}"
    _wait_record(arc, registry_id, record_id, "APPROVED")

    found = _wait_discoverable(
        lambda: ar.search_discoverable_registry_records(searchQuery=record_name, registryIds=[registry_id])
    )
    search_records = found["registryRecords"]
    assert len(search_records) == 1, (
        f"expected exactly the one published record from SearchDiscoverableRegistryRecords, "
        f"got {len(search_records)}: {search_records!r}"
    )
    search_hit = search_records[0]
    assert search_hit["recordId"] == record_id, (
        f"search returned recordId {search_hit['recordId']!r}, expected {record_id!r}"
    )
    assert search_hit["name"] == record_name, (
        f"search returned name {search_hit['name']!r}, expected {record_name!r}"
    )
    assert search_hit["status"] == "APPROVED", (
        f"search returned status {search_hit['status']!r}, expected APPROVED"
    )
    assert search_hit["recordType"] == "CUSTOM", (
        f"search returned recordType {search_hit['recordType']!r}, expected CUSTOM"
    )
    assert search_hit["descriptors"]["custom"]["data"] == json.dumps({"summary": description}), (
        f"search returned descriptor data {search_hit['descriptors']!r}, expected the published content"
    )

    batch = ar.batch_get_discoverable_registry_record(
        entries=[{"registryId": registry_id, "recordIds": [record_id]}]
    )
    assert batch["errors"] == [], f"expected no per-record errors, got {batch['errors']!r}"
    batch_records = batch["registryRecords"]
    assert len(batch_records) == 1, (
        f"expected exactly the one published record from BatchGetDiscoverableRegistryRecord, "
        f"got {len(batch_records)}: {batch_records!r}"
    )
    batch_hit = batch_records[0]
    assert batch_hit["recordId"] == record_id, (
        f"batch-get returned recordId {batch_hit['recordId']!r}, expected {record_id!r}"
    )
    assert batch_hit["name"] == record_name, (
        f"batch-get returned name {batch_hit['name']!r}, expected {record_name!r}"
    )
    assert batch_hit["status"] == "APPROVED", (
        f"batch-get returned status {batch_hit['status']!r}, expected APPROVED"
    )
    assert batch_hit["descriptors"]["custom"]["data"] == json.dumps({"summary": description}), (
        f"batch-get returned descriptor data {batch_hit['descriptors']!r}, expected the published content"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
