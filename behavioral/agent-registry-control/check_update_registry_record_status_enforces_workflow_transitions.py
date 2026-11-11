"""update-registry-record-status-enforces-workflow-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-registry-record-status-enforces-workflow-transitions"
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


def _error(fn):
    """(Error.Code, Error.Message) the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the status change to be rejected, but it succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRegistryRecordStatus refuses PENDING_APPROVAL as an explicit target status, leaving
    a DRAFT record unchanged, while the documented submit-then-approve path still succeeds.
    """
    arc = ctx.client("agent-registry-control")

    registry_name = ctx.unique_name("sim2real-behav-arc-reg-")
    registry = arc.create_registry(name=registry_name)
    registry_id = registry["registryArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(lambda: arc.delete_registry(registryId=registry_id), "ResourceNotFoundException"))
    _wait_registry(arc, registry_id, "READY")

    record_name = ctx.unique_name("sim2real-behav-arc-rec-")
    record = arc.create_registry_record(
        registryId=registry_id, name=record_name, recordType="CUSTOM", descriptors={"custom": {"data": "{}"}},
    )
    record_id = record["recordArn"].split("/")[-1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=registry_id, recordId=record_id),
        "ResourceNotFoundException",
    ))
    _wait_record(arc, registry_id, record_id, "DRAFT")

    code, message = _error(lambda: arc.update_registry_record_status(
        registryId=registry_id, recordId=record_id, status="PENDING_APPROVAL", statusReason="skip review",
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "Invalid target status: PENDING_APPROVAL", f"unexpected message {message!r}"

    unchanged = arc.get_registry_record(registryId=registry_id, recordId=record_id)
    assert unchanged["status"] == "DRAFT", (
        f"the refused status change still moved the record to {unchanged['status']!r}"
    )

    # Positive control: the documented path (submit, then approve) succeeds on the same record.
    submitted = arc.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)
    assert submitted["status"] == "PENDING_APPROVAL", (
        f"expected PENDING_APPROVAL after a proper submission, got {submitted['status']!r}"
    )
    approved = arc.update_registry_record_status(
        registryId=registry_id, recordId=record_id, status="APPROVED", statusReason="looks good",
    )
    assert approved["status"] == "APPROVED", (
        f"expected APPROVED once submitted, got {approved['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
