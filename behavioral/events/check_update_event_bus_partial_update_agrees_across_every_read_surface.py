"""update-event-bus-partial-update-agrees-across-every-read-surface."""

from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-event-bus-partial-update-agrees-across-every-read-surface"
GROUP = "event-bus"
SERVICES = ["events"]

_MAX_DESCRIPTION = 512  # model constant: EventBusDescription @length(max: 512)
# The subset of DescribeEventBusResponse that UpdateEventBusResponse also carries. Policy,
# CreationTime and LastModifiedTime are excluded because UpdateEventBus does not return them.
_SHARED_FIELDS = ("Name", "Arn", "Description", "KmsKeyIdentifier", "DeadLetterConfig", "LogConfig")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A partial UpdateEventBus preserves the field it does not name and agrees with
    DescribeEventBus and ListEventBuses; LogConfig needs both sub-fields; the 512-char Description
    limit holds on create and update.
    """
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    first_description = f"sim2real desc {uuid.uuid4().hex}"
    log_config = {"IncludeDetail": "FULL", "Level": "TRACE"}

    # No CloudWatch Logs destination is needed for CreateEventBus to accept LogConfig.
    created = events.create_event_bus(
        Name=bus, Description=first_description, LogConfig=dict(log_config), Tags=_tags_kv()
    )
    ctx.on_cleanup(lambda n=bus: _delete_bus_quietly(ctx, n))
    assert created["EventBusArn"].endswith(f"/{bus}"), (
        f"CreateEventBus must return an ARN ending in /{bus}, got {created['EventBusArn']!r}"
    )

    # --- positive control + representation: both authored fields come back through a different op. ---
    described = events.describe_event_bus(Name=bus)
    assert described["Description"] == first_description, (
        f"DescribeEventBus must echo the Description set at create: expected "
        f"{first_description!r}, got {described.get('Description')!r}"
    )
    assert described.get("LogConfig") == log_config, (
        f"DescribeEventBus must echo the LogConfig set at create: expected {log_config}, got "
        f"{described.get('LogConfig')!r} (H1 — if CreateEventBus refused LogConfig outright, the "
        f"refusal is the contract and this check must be re-shaped to assert it)"
    )

    # --- the partial update: name ONLY Description, then hold the two surfaces to each other. ---
    second_description = f"sim2real desc {uuid.uuid4().hex}"
    updated = events.update_event_bus(Name=bus, Description=second_description)
    reread = events.describe_event_bus(Name=bus)
    assert reread["Description"] == second_description, (
        f"the field the update named must change: expected Description={second_description!r}, "
        f"DescribeEventBus reports {reread.get('Description')!r}"
    )
    _assert_surfaces_agree(updated, reread, label="Description-only UpdateEventBus")
    assert reread.get("LogConfig") == log_config, (
        f"a partial UpdateEventBus naming only Description must PRESERVE LogConfig untouched "
        f"(H2 measured: preserve, not clear): expected {log_config}, DescribeEventBus reports "
        f"{reread.get('LogConfig')!r}"
    )

    # --- ListEventBuses is a third, independent surface and must agree on Description. ---
    rows = [b for b in events.list_event_buses(NamePrefix=bus).get("EventBuses", []) if b["Name"] == bus]
    assert len(rows) == 1, (
        f"ListEventBuses(NamePrefix={bus!r}) must return exactly one row for the bus, got "
        f"{[b.get('Name') for b in events.list_event_buses(NamePrefix=bus).get('EventBuses', [])]}"
    )
    assert rows[0].get("Description") == second_description, (
        f"the ListEventBuses row must carry the same Description as DescribeEventBus: expected "
        f"{second_description!r}, got {rows[0].get('Description')!r}"
    )
    assert rows[0].get("Arn") == reread["Arn"], (
        f"the ListEventBuses row and DescribeEventBus must report the same ARN: "
        f"{rows[0].get('Arn')!r} vs {reread['Arn']!r}"
    )

    # --- LogConfig is an atomic struct on UpdateEventBus, not a field-by-field patch:
    # naming it at all requires BOTH sub-fields; omitting either is refused and leaves it untouched. ---
    missing_level = _error(lambda: events.update_event_bus(Name=bus, LogConfig={"IncludeDetail": "NONE"}),
                           "UpdateEventBus with LogConfig missing Level")
    assert missing_level[0] == "ValidationException" and "Level" in missing_level[1], (
        f"UpdateEventBus with LogConfig missing Level must be refused naming the missing field: "
        f"got {missing_level!r}"
    )
    missing_include_detail = _error(lambda: events.update_event_bus(Name=bus, LogConfig={"Level": "OFF"}),
                                    "UpdateEventBus with LogConfig missing IncludeDetail")
    assert missing_include_detail[0] == "ValidationException" and "IncludeDetail" in missing_include_detail[1], (
        f"UpdateEventBus with LogConfig missing IncludeDetail must be refused naming the missing "
        f"field: got {missing_include_detail!r}"
    )
    untouched = events.describe_event_bus(Name=bus)
    assert untouched.get("LogConfig") == log_config, (
        f"both refused, partially-specified LogConfig updates must leave the bus's LogConfig "
        f"untouched: expected {log_config}, DescribeEventBus reports {untouched.get('LogConfig')!r}"
    )

    # --- the mirror-image partial update: name ONLY LogConfig, with both sub-fields the service
    # requires — Description must survive untouched, the same way LogConfig survived above. ---
    log_only = events.update_event_bus(Name=bus, LogConfig={"IncludeDetail": "NONE", "Level": "OFF"})
    after_log = events.describe_event_bus(Name=bus)
    assert (after_log.get("LogConfig") or {}).get("Level") == "OFF", (
        f"the field the update named must change: expected LogConfig.Level='OFF', "
        f"DescribeEventBus reports {after_log.get('LogConfig')!r} (H5)"
    )
    assert after_log.get("Description") == second_description, (
        f"a partial UpdateEventBus naming only LogConfig must PRESERVE Description untouched: "
        f"expected {second_description!r}, DescribeEventBus reports {after_log.get('Description')!r}"
    )
    _assert_surfaces_agree(log_only, after_log, label="LogConfig-only UpdateEventBus")

    # --- the Description length boundary, on both write paths, with the effect proven absent. ---
    at_max = "d" * _MAX_DESCRIPTION
    events.update_event_bus(Name=bus, Description=at_max)
    assert events.describe_event_bus(Name=bus)["Description"] == at_max, (
        f"a Description of exactly the documented maximum {_MAX_DESCRIPTION} characters must be "
        f"stored verbatim; DescribeEventBus reports "
        f"{len(events.describe_event_bus(Name=bus).get('Description') or '')} characters"
    )
    # botocore does not validate string maxima, so the over-length value reaches the service.
    update_refusal = _error(
        lambda: events.update_event_bus(Name=bus, Description="d" * (_MAX_DESCRIPTION + 1)),
        f"UpdateEventBus with a {_MAX_DESCRIPTION + 1}-character Description (the documented "
        f"{_MAX_DESCRIPTION}-character limit must be enforced by the service)",
    )
    assert events.describe_event_bus(Name=bus)["Description"] == at_max, (
        f"the refused over-length update must not have written: expected the {_MAX_DESCRIPTION}"
        f"-character Description to survive, got "
        f"{events.describe_event_bus(Name=bus).get('Description')!r}"
    )

    over_long_bus = ctx.unique_name("sim2real-behav-bus-")
    ctx.on_cleanup(lambda n=over_long_bus: _delete_bus_quietly(ctx, n))
    create_refusal = _error(
        lambda: events.create_event_bus(
            Name=over_long_bus, Description="d" * (_MAX_DESCRIPTION + 1), Tags=_tags_kv()
        ),
        f"CreateEventBus with a {_MAX_DESCRIPTION + 1}-character Description (both write paths "
        f"must enforce the same documented limit)",
    )
    assert create_refusal[0] == update_refusal[0], (
        f"the create and update paths must refuse an over-length Description with the same error "
        f"code: create gave {create_refusal[0]!r}, update gave {update_refusal[0]!r} (H4)"
    )
    absent = _error(lambda: events.describe_event_bus(Name=over_long_bus),
                    f"DescribeEventBus of the refused bus {over_long_bus}")
    assert absent[0] == "ResourceNotFoundException", (
        f"the refused CreateEventBus must not have created a bus: "
        f"DescribeEventBus({over_long_bus}) returned {absent[0]!r}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": _MANAGED_TAG_KEY, "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]


def _assert_surfaces_agree(mutation_response: dict, read_response: dict, *, label: str) -> None:
    """Every field UpdateEventBus and DescribeEventBus have in common must carry the same value.

    Callers pair it with a direct assertion on the updated field, since two empty surfaces agree.
    """
    mutated = {f: mutation_response.get(f) for f in _SHARED_FIELDS}
    read = {f: read_response.get(f) for f in _SHARED_FIELDS}
    disagreements = {f: (mutated[f], read[f]) for f in _SHARED_FIELDS if mutated[f] != read[f]}
    assert disagreements == {}, (
        f"{label}: the mutating call and the independent read disagree on "
        f"{sorted(disagreements)} — (UpdateEventBus, DescribeEventBus) pairs were "
        f"{json.dumps(disagreements, default=str)[:300]}"
    )


def _error(fn, what: str = "the call") -> tuple[str, str]:
    """(code, message) for a call expected to fail; a success raises, naming what."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"{what} SUCCEEDED where real EventBridge refuses it: {result!r}")


def _delete_bus_quietly(ctx, name: str) -> None:
    """Teardown; the bus may never have been created (one leg deliberately fails to create it)."""
    try:
        ctx.client("events").delete_event_bus(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise RuntimeError(f"could not delete event bus {name}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
