"""list-event-types-filter-by-service-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-event-types-filter-by-service-name"
GROUP = "listing"
SERVICES = ["codestar-notifications"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEventTypes with a SERVICE_NAME filter returns only event types for that service."""
    csn = ctx.client("codestar-notifications")
    resp = csn.list_event_types(Filters=[{"Name": "SERVICE_NAME", "Value": "CodeDeploy"}], MaxResults=100)
    event_types = resp["EventTypes"]

    assert len(event_types) > 0, f"expected at least one CodeDeploy event type, got {event_types!r}"
    for event_type in event_types:
        assert event_type["ServiceName"] == "CodeDeploy", (
            f"expected ServiceName=CodeDeploy for every filtered entry, got {event_type!r}"
        )

    ids = {e["EventTypeId"] for e in event_types}
    assert "codedeploy-application-deployment-succeeded" in ids, (
        f"expected 'codedeploy-application-deployment-succeeded' in filtered ids, got {sorted(ids)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
