"""approval-configuration-update-affects-only-future-submissions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "approval-configuration-update-affects-only-future-submissions"
GROUP = 'approval-workflow'
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


@tags("axis:happy-path", "cap:c4", "plane:control")
def run(ctx) -> None:
    """Adding an auto-approval rule to a registry does not retroactively approve a record that
    is already PENDING_APPROVAL; only a record submitted after the change is auto-approved.
    """
    arc = ctx.client("agent-registry-control")

    registry_name = ctx.unique_name("sim2real-behav-arc-reg-")
    registry = arc.create_registry(name=registry_name)
    registry_id = registry["registryArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(lambda: arc.delete_registry(registryId=registry_id), "ResourceNotFoundException"))
    _wait_registry(arc, registry_id, "READY")

    before_name = ctx.unique_name("sim2real-behav-arc-before-")
    before = arc.create_registry_record(
        registryId=registry_id, name=before_name, recordType="CUSTOM", descriptors={"custom": {"data": "{}"}},
    )
    before_id = before["recordArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=registry_id, recordId=before_id),
        "ResourceNotFoundException",
    ))
    _wait_record(arc, registry_id, before_id, "DRAFT")

    submitted_before = arc.submit_registry_record_for_approval(registryId=registry_id, recordId=before_id)
    assert submitted_before["status"] == "PENDING_APPROVAL", (
        f"expected PENDING_APPROVAL with no auto-approval rule yet, got {submitted_before['status']!r}"
    )

    arc.update_registry(
        registryId=registry_id,
        approvalConfiguration={"optionalValue": {"autoApprovalRules": ["APPROVE_ALL"]}},
    )
    _wait_registry(arc, registry_id, "READY")

    unaffected = arc.get_registry_record(registryId=registry_id, recordId=before_id)
    assert unaffected["status"] == "PENDING_APPROVAL", (
        "adding an auto-approval rule retroactively changed an already-pending record to "
        f"{unaffected['status']!r}"
    )

    after_name = ctx.unique_name("sim2real-behav-arc-after-")
    after = arc.create_registry_record(
        registryId=registry_id, name=after_name, recordType="CUSTOM", descriptors={"custom": {"data": "{}"}},
    )
    after_id = after["recordArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=registry_id, recordId=after_id),
        "ResourceNotFoundException",
    ))
    _wait_record(arc, registry_id, after_id, "DRAFT")

    submitted_after = arc.submit_registry_record_for_approval(registryId=registry_id, recordId=after_id)
    assert submitted_after["status"] == "APPROVED", (
        f"a record submitted after the auto-approval rule was added stayed {submitted_after['status']!r}"
    )

    # The earlier record is still waiting on a human; approve it explicitly to confirm it is
    # merely pending and not stuck.
    resolved_before = arc.update_registry_record_status(
        registryId=registry_id, recordId=before_id, status="APPROVED", statusReason="manual catch-up",
    )
    assert resolved_before["status"] == "APPROVED", (
        f"expected the still-pending record to accept a manual approval, got {resolved_before['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
