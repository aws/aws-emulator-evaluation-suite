"""list-registry-records-filter-by-status-excludes-other-statuses."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-registry-records-filter-by-status-excludes-other-statuses"
GROUP = 'registry-lifecycle'
SERVICES = ['agent-registry-control']


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


def _names_with_status(client, registry_id: str, status: str) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"registryId": registry_id, "filters": [{"name": "status", "values": [status]}]}
        if token:
            kwargs["nextToken"] = token
        page = client.list_registry_records(**kwargs)
        names |= {r["name"] for r in page["registryRecords"]}
        token = page.get("nextToken")
        if not token:
            return names


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRegistryRecords' status filter returns exactly the records in that status and no
    others, for two records in the same registry that have diverged to different statuses.
    """
    arc = ctx.client("agent-registry-control")

    registry_name = ctx.unique_name("sim2real-behav-arc-reg-")
    registry = arc.create_registry(name=registry_name)
    registry_id = registry["registryArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(lambda: arc.delete_registry(registryId=registry_id), "ResourceNotFoundException"))
    _wait_registry(arc, registry_id, "READY")

    draft_name = ctx.unique_name("sim2real-behav-arc-draft-")
    draft = arc.create_registry_record(
        registryId=registry_id, name=draft_name, recordType="CUSTOM", descriptors={"custom": {"data": "{}"}},
    )
    draft_id = draft["recordArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=registry_id, recordId=draft_id),
        "ResourceNotFoundException",
    ))
    _wait_record(arc, registry_id, draft_id, "DRAFT")

    approved_name = ctx.unique_name("sim2real-behav-arc-approved-")
    approved = arc.create_registry_record(
        registryId=registry_id, name=approved_name, recordType="CUSTOM", descriptors={"custom": {"data": "{}"}},
    )
    approved_id = approved["recordArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=registry_id, recordId=approved_id),
        "ResourceNotFoundException",
    ))
    _wait_record(arc, registry_id, approved_id, "DRAFT")
    arc.submit_registry_record_for_approval(registryId=registry_id, recordId=approved_id)
    arc.update_registry_record_status(
        registryId=registry_id, recordId=approved_id, status="APPROVED", statusReason="ok",
    )

    draft_names = _names_with_status(arc, registry_id, "DRAFT")
    assert draft_names == {draft_name}, (
        f"DRAFT filter returned {sorted(draft_names)}, expected only {draft_name!r}"
    )

    approved_names = _names_with_status(arc, registry_id, "APPROVED")
    assert approved_names == {approved_name}, (
        f"APPROVED filter returned {sorted(approved_names)}, expected only {approved_name!r}"
    )

    pending_names = _names_with_status(arc, registry_id, "PENDING_APPROVAL")
    assert pending_names == set(), (
        f"PENDING_APPROVAL filter returned {sorted(pending_names)}, expected none"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
