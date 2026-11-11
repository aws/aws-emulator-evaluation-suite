"""delete-registry-blocked-while-records-exist."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-registry-blocked-while-records-exist"
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


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the delete to be rejected, but it succeeded: {result!r}")


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


def _wait_registry_gone(client, registry_id: str, *, budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            client.get_registry(registryId=registry_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        assert time.monotonic() < deadline, f"registry still visible after {budget_s}s"
        time.sleep(3)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRegistry refuses a registry that still holds records, leaving the registry intact,
    and succeeds once every record under it is gone.
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

    code, message = _error(lambda: arc.delete_registry(registryId=registry_id))
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == (
        f"Cannot delete registry '{registry['registryArn']}' because it contains registry records. "
        "Delete all registry records before deleting the registry."
    ), f"unexpected message {message!r}"

    still_there = arc.get_registry(registryId=registry_id)
    assert still_there["status"] == "READY", (
        f"the refused delete still disturbed the registry, now {still_there['status']!r}"
    )

    # Positive control: removing the record first lets the delete succeed.
    arc.delete_registry_record(registryId=registry_id, recordId=record_id)
    deleted = arc.delete_registry(registryId=registry_id)
    assert deleted["status"] == "DELETING", (
        f"expected DELETING once the registry was empty, got {deleted['status']!r}"
    )
    _wait_registry_gone(arc, registry_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
