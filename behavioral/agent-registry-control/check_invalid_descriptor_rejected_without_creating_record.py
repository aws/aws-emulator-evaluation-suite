"""invalid-descriptor-rejected-without-creating-record."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-descriptor-rejected-without-creating-record"
GROUP = "descriptor-validation"
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


def _ids_named(arc, registry_id: str, name: str) -> list[str]:
    page = arc.list_registry_records(registryId=registry_id, filters=[{"name": "name", "values": [name]}])
    assert not page.get("nextToken"), "a name filter over the check's own registry spans pages"
    return [r["recordId"] for r in page["registryRecords"]]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRegistryRecord refuses a CUSTOM descriptor that is not JSON and an MCP descriptor no
    MCP server schema version accepts, creating no record, while a valid MCP descriptor creates one.
    """
    arc = ctx.client("agent-registry-control")
    registry_id, _ = _create_registry(ctx, arc)

    not_json = ctx.unique_name("sim2real-behav-arc-rec-")
    code, message = _error(lambda: arc.create_registry_record(
        registryId=registry_id, name=not_json, recordType="CUSTOM",
        descriptors={"custom": {"data": "not json"}},
    ))
    assert code == "ValidationException", f"non-JSON data: expected ValidationException, got {code}: {message!r}"
    assert message == (
        "data is not valid JSON: Unrecognized token 'not': was expecting "
        "(JSON String, Number, Array, Object or token 'null', 'true' or 'false')"
    ), f"non-JSON data: unexpected message {message!r}"

    off_schema = ctx.unique_name("sim2real-behav-arc-rec-")
    code, message = _error(lambda: arc.create_registry_record(
        registryId=registry_id, name=off_schema, recordType="MCP",
        descriptors={"mcpServer": {"data": json.dumps({"x": 1})}},
    ))
    assert code == "ValidationException", f"MCP data: expected ValidationException, got {code}: {message!r}"
    assert message == "mcp.server data does not match any supported version", (
        f"MCP data: unexpected message {message!r}"
    )
    assert _ids_named(arc, registry_id, not_json) == [], "the refused CUSTOM record exists"
    assert _ids_named(arc, registry_id, off_schema) == [], "the refused MCP record exists"

    server = {"name": "io.example/weather", "description": "Weather MCP server", "version": "1.0.0"}
    valid_name = ctx.unique_name("sim2real-behav-arc-rec-")
    record_id, _ = _create_record(
        ctx, arc, registry_id, valid_name, recordType="MCP",
        descriptors={"mcpServer": {"data": json.dumps(server)}},
    )
    got = arc.get_registry_record(registryId=registry_id, recordId=record_id)
    assert got["recordType"] == "MCP", f"recordType is {got['recordType']!r}"
    assert json.loads(got["descriptors"]["mcpServer"]["data"]) == server, (
        f"the stored MCP descriptor differs: {got['descriptors']!r}"
    )
    assert _ids_named(arc, registry_id, valid_name) == [record_id], "the valid record is not listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
