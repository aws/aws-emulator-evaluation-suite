"""auto-approval-rule-skips-manual-review."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auto-approval-rule-skips-manual-review"
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


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registry's APPROVE_ALL rule auto-approves a submission; one without any rule leaves
    the record pending manual review instead.
    """
    arc = ctx.client("agent-registry-control")

    auto_name = ctx.unique_name("sim2real-behav-arc-auto-")
    auto = arc.create_registry(
        name=auto_name, approvalConfiguration={"autoApprovalRules": ["APPROVE_ALL"]}
    )
    auto_id = auto["registryArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(lambda: arc.delete_registry(registryId=auto_id), "ResourceNotFoundException"))
    _wait_registry(arc, auto_id, "READY")

    manual_name = ctx.unique_name("sim2real-behav-arc-manual-")
    manual = arc.create_registry(name=manual_name)
    manual_id = manual["registryArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(lambda: arc.delete_registry(registryId=manual_id), "ResourceNotFoundException"))
    _wait_registry(arc, manual_id, "READY")

    auto_rec = arc.create_registry_record(
        registryId=auto_id, name=ctx.unique_name("sim2real-behav-arc-rec-"),
        recordType="CUSTOM", descriptors={"custom": {"data": "{}"}},
    )
    auto_rec_id = auto_rec["recordArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=auto_id, recordId=auto_rec_id),
        "ResourceNotFoundException",
    ))
    _wait_record(arc, auto_id, auto_rec_id, "DRAFT")

    manual_rec = arc.create_registry_record(
        registryId=manual_id, name=ctx.unique_name("sim2real-behav-arc-rec-"),
        recordType="CUSTOM", descriptors={"custom": {"data": "{}"}},
    )
    manual_rec_id = manual_rec["recordArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=manual_id, recordId=manual_rec_id),
        "ResourceNotFoundException",
    ))
    _wait_record(arc, manual_id, manual_rec_id, "DRAFT")

    auto_submitted = arc.submit_registry_record_for_approval(registryId=auto_id, recordId=auto_rec_id)
    assert auto_submitted["status"] == "APPROVED", (
        f"APPROVE_ALL registry left the record at {auto_submitted['status']!r} instead of auto-approving it"
    )

    manual_submitted = arc.submit_registry_record_for_approval(registryId=manual_id, recordId=manual_rec_id)
    assert manual_submitted["status"] == "PENDING_APPROVAL", (
        f"a registry with no auto-approval rule produced {manual_submitted['status']!r} "
        "instead of leaving the record for manual review"
    )

    got_manual = arc.get_registry_record(registryId=manual_id, recordId=manual_rec_id)
    assert got_manual["status"] == "PENDING_APPROVAL", (
        f"a later read shows {got_manual['status']!r}, not the PENDING_APPROVAL the submission produced"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
