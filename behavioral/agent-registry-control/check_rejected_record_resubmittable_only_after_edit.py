"""rejected-record-resubmittable-only-after-edit."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rejected-record-resubmittable-only-after-edit"
GROUP = "approval-workflow"
SERVICES = ["agent-registry-control"]

_REGISTRY_CAP_S = 240.0
_RECORD_CAP_S = 120.0


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
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, cap_s, what):
    """probe() until done(result); a wait the run budget cut short is not graded."""
    budget = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + budget
    while True:
        got = probe()
        if done(got):
            return got
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} not reached within {budget:.0f}s; last read {got!r}")
        time.sleep(2)


def _wait_registry(ctx, arc, registry_id: str) -> dict:
    def done(got):
        assert not got["status"].endswith("FAILED"), f"registry entered {got['status']!r}: {got!r}"
        return got["status"] == "READY"

    return _poll(ctx, lambda: arc.get_registry(registryId=registry_id), done, _REGISTRY_CAP_S,
                 "registry READY")


def _wait_record(ctx, arc, registry_id: str, record_id: str, until: str) -> dict:
    def done(got):
        assert not got["status"].endswith("FAILED"), f"record entered {got['status']!r}: {got!r}"
        return got["status"] == until

    return _poll(ctx, lambda: arc.get_registry_record(registryId=registry_id, recordId=record_id),
                 done, _RECORD_CAP_S, f"record {until}")


def _create_registry(ctx, arc, **kwargs) -> tuple[str, str]:
    """A READY registry of the check's own, deleted at cleanup; returns (id, arn)."""
    arn = arc.create_registry(name=ctx.unique_name("sim2real-behav-arc-reg-"), **kwargs)["registryArn"]
    registry_id = arn.rsplit("/", 1)[1]
    ctx.on_cleanup(_teardown(lambda: arc.delete_registry(registryId=registry_id),
                             "ResourceNotFoundException"))
    _wait_registry(ctx, arc, registry_id)
    return registry_id, arn


def _create_record(ctx, arc, registry_id: str, name: str, **kwargs) -> tuple[str, str]:
    """A DRAFT CUSTOM record (unless kwargs say otherwise), deleted at cleanup; returns (id, arn)."""
    kwargs.setdefault("recordType", "CUSTOM")
    kwargs.setdefault("descriptors", {"custom": {"data": "{}"}})
    arn = arc.create_registry_record(registryId=registry_id, name=name, **kwargs)["recordArn"]
    record_id = arn.rsplit("/", 1)[1]
    ctx.on_cleanup(_teardown(
        lambda: arc.delete_registry_record(registryId=registry_id, recordId=record_id),
        "ResourceNotFoundException",
    ))
    _wait_record(ctx, arc, registry_id, record_id, "DRAFT")
    return record_id, arn


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A REJECTED record cannot be resubmitted as it is; editing it returns it to DRAFT with the
    edit applied, and the edited record can then be submitted again.
    """
    arc = ctx.client("agent-registry-control")
    registry_id, _ = _create_registry(ctx, arc)
    record_id, _ = _create_record(ctx, arc, registry_id, ctx.unique_name("sim2real-behav-arc-rec-"))
    arc.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)
    rejected = arc.update_registry_record_status(
        registryId=registry_id, recordId=record_id, status="REJECTED", statusReason="needs a description",
    )
    assert rejected["status"] == "REJECTED", f"expected REJECTED, got {rejected['status']!r}"

    code, message = _error(
        lambda: arc.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "Cannot submit the record for approval in current status: REJECTED", (
        f"unexpected message {message!r}"
    )
    status = arc.get_registry_record(registryId=registry_id, recordId=record_id)["status"]
    assert status == "REJECTED", f"the refused resubmission moved the record to {status!r}"

    arc.update_registry_record(
        registryId=registry_id, recordId=record_id,
        description={"optionalValue": "Tide tables for harbor pilots"},
    )
    edited = _wait_record(ctx, arc, registry_id, record_id, "DRAFT")
    assert edited["description"] == "Tide tables for harbor pilots", (
        f"the edit that reopened the record did not apply: {edited.get('description')!r}"
    )
    resubmitted = arc.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)
    assert resubmitted["status"] == "PENDING_APPROVAL", (
        f"expected the edited record to enter PENDING_APPROVAL, got {resubmitted['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
