"""start-schema-creation-invalid-sdl-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "start-schema-creation-invalid-sdl-fails"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

VALID_SDL = (
    "type Query {\n"
    "  ping: String\n"
    "}\n\n"
    "schema {\n"
    "  query: Query\n"
    "}\n"
)

@tags("cap:c1", "cap:c4", "plane:control", "axis:rejection")
def run(ctx) -> None:
    """StartSchemaCreation with malformed SDL is accepted (PROCESSING) and then ends FAILED with
    details, while valid SDL on a separate API reaches SUCCESS."""
    svc = ctx.client("appsync")

    control_api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-ctl-"),
        authenticationType="API_KEY",
        tags={"sim2real": "audit"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=control_api: svc.delete_graphql_api(apiId=_a["apiId"]))
    control_api_id = control_api["apiId"]

    control_start = svc.start_schema_creation(apiId=control_api_id, definition=VALID_SDL)
    assert control_start["status"] in ("PROCESSING", "SUCCESS", "ACTIVE"), (
        f"positive control: expected PROCESSING/SUCCESS/ACTIVE from StartSchemaCreation with "
        f"valid SDL, got {control_start!r}"
    )

    def control_probe():
        return svc.get_schema_creation_status(apiId=control_api_id)

    control_final = _poll_until(
        control_probe,
        lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=2,
        description="positive control schema creation reaching a terminal state",
    )
    assert control_final["status"] in ("SUCCESS", "ACTIVE"), (
        f"positive control: valid SDL was expected to reach terminal SUCCESS/ACTIVE, got "
        f"{control_final!r} — the account/call shape cannot be assumed healthy, so a FAILED "
        f"result below would not be attributable to the malformed SDL specifically"
    )

    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "audit"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    bad_definition = "type Foo { this is not valid graphql @@@ }"

    start = svc.start_schema_creation(apiId=api_id, definition=bad_definition)
    assert start["status"] in ("PROCESSING", "FAILED"), (
        f"expected PROCESSING or FAILED from StartSchemaCreation with malformed SDL, got "
        f"{start['status']!r}: {start!r}"
    )

    def probe():
        return svc.get_schema_creation_status(apiId=api_id)

    final = _poll_until(
        probe,
        lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=2,
        description="schema creation with malformed SDL reaching a terminal state",
    )
    assert final["status"] == "FAILED", f"expected terminal FAILED for malformed SDL, got {final}"
    assert final.get("details"), (
        f"expected a non-empty failure detail message, got details={final.get('details')!r} "
        f"(full response: {final!r})"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
