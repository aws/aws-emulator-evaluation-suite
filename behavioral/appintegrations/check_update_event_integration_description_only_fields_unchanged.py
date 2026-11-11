"""update-event-integration-description-only-fields-unchanged."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-event-integration-description-only-fields-unchanged"
GROUP = "state"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEventIntegration changes only Description; EventFilter/EventBridgeBus remain immutable."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-evt-upd-")

    appi.create_event_integration(
        Name=name,
        Description="before-update",
        EventFilter={"Source": "aws.cases"},
        EventBridgeBus="default",
    )
    ctx.on_cleanup(lambda: appi.delete_event_integration(Name=name))

    appi.update_event_integration(Name=name, Description="after-update")

    got = appi.get_event_integration(Name=name)
    assert got["Description"] == "after-update", (
        f"expected Description updated to 'after-update', got {got['Description']!r}"
    )
    assert got["EventFilter"]["Source"] == "aws.cases", (
        f"expected EventFilter.Source unchanged at 'aws.cases', got {got['EventFilter']!r}"
    )
    assert got["EventBridgeBus"] == "default", (
        f"expected EventBridgeBus unchanged at 'default', got {got['EventBridgeBus']!r}"
    )
    assert got["Name"] == name, f"expected Name unchanged at {name!r}, got {got['Name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
