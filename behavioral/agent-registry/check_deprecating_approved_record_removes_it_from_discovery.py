"""deprecating-approved-record-removes-it-from-discovery."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deprecating-approved-record-removes-it-from-discovery"
GROUP = "discovery"
SERVICES = ["agent-registry"]

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


def _listed(ar, registry_id: str, **kwargs) -> dict[str, dict]:
    """Discoverable records of the registry by name, across every page."""
    found, token = {}, None
    while True:
        page = ar.list_discoverable_registry_records(
            registryId=registry_id, **kwargs, **({"nextToken": token} if token else {})
        )
        found.update({r["name"]: r for r in page["registryRecords"]})
        token = page.get("nextToken")
        if not token:
            return found


def _approve(arc, registry_id: str, record_id: str) -> None:
    arc.submit_registry_record_for_approval(registryId=registry_id, recordId=record_id)
    approved = arc.update_registry_record_status(
        registryId=registry_id, recordId=record_id, status="APPROVED", statusReason="reviewed",
    )
    assert approved["status"] == "APPROVED", f"expected APPROVED, got {approved['status']!r}"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Deprecating an approved record withdraws it from ListDiscoverableRegistryRecords and from
    BatchGetDiscoverableRegistryRecord, while a sibling approved record stays discoverable.
    """
    arc = ctx.client("agent-registry-control")
    ar = ctx.client("agent-registry")
    registry_id, _ = _create_registry(ctx, arc)
    keep_name = ctx.unique_name("sim2real-behav-ar-rec-")
    retire_name = ctx.unique_name("sim2real-behav-ar-rec-")
    keep_id, _ = _create_record(ctx, arc, registry_id, keep_name)
    retire_id, _ = _create_record(ctx, arc, registry_id, retire_name)
    _approve(arc, registry_id, keep_id)
    _approve(arc, registry_id, retire_id)
    _poll(ctx, lambda: _listed(ar, registry_id), lambda got: {keep_name, retire_name} <= set(got),
          _RECORD_CAP_S, "both approved records listed")

    arc.update_registry_record_status(
        registryId=registry_id, recordId=retire_id, status="DEPRECATED", statusReason="retired",
    )
    listed = _poll(ctx, lambda: _listed(ar, registry_id), lambda got: retire_name not in got,
                   _RECORD_CAP_S, "deprecated record withdrawn")
    assert sorted(listed) == [keep_name], f"expected only {keep_name!r} listed, got {sorted(listed)!r}"

    got = ar.batch_get_discoverable_registry_record(
        entries=[{"registryId": registry_id, "recordIds": [keep_id, retire_id]}]
    )
    assert [r["recordId"] for r in got["registryRecords"]] == [keep_id], (
        f"expected only the kept record served, got {[r['recordId'] for r in got['registryRecords']]!r}"
    )
    assert got["errors"] == [
        {"registryId": registry_id, "recordId": retire_id, "errorCode": "RESOURCE_NOT_FOUND"}
    ], f"unexpected per-record errors {got['errors']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
