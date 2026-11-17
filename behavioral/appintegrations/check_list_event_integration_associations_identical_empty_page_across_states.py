"""list-event-integration-associations-identical-empty-page-across-states."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-event-integration-associations-identical-empty-page-across-states"
GROUP = "state"
SERVICES = ["appintegrations"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _associations(appi, name):
    return appi.list_event_integration_associations(EventIntegrationName=name)


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEventIntegrationAssociations answers the same empty page, with no NextToken, for a
    live event integration, that same name once deleted, and a name never created; only
    GetEventIntegration tells the deleted name apart, refusing it with ResourceNotFoundException.
    """
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-eia-")
    never_created_name = ctx.unique_name("sim2real-eia-gone-")

    appi.create_event_integration(
        Name=name,
        EventFilter={"Source": "aws.cases"},
        EventBridgeBus="default",
    )

    def _delete() -> None:
        try:
            appi.delete_event_integration(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)

    # positive control: the integration exists and is readable right after create
    live = appi.get_event_integration(Name=name)
    assert live["Name"] == name, f"expected GetEventIntegration Name {name!r}, got {live['Name']!r}"

    live_page = _associations(appi, name)
    assert live_page["EventIntegrationAssociations"] == [], (
        f"expected an empty associations list for live {name!r}, "
        f"got {live_page['EventIntegrationAssociations']!r}"
    )
    assert "NextToken" not in live_page, (
        f"expected no NextToken for live {name!r}, got {live_page.get('NextToken')!r}"
    )

    appi.delete_event_integration(Name=name)

    deleted_page = _associations(appi, name)
    assert deleted_page["EventIntegrationAssociations"] == [], (
        f"expected an empty associations list for deleted {name!r}, "
        f"got {deleted_page['EventIntegrationAssociations']!r}"
    )
    assert "NextToken" not in deleted_page, (
        f"expected no NextToken for deleted {name!r}, got {deleted_page.get('NextToken')!r}"
    )

    never_page = _associations(appi, never_created_name)
    assert never_page["EventIntegrationAssociations"] == [], (
        f"expected an empty associations list for never-created {never_created_name!r}, "
        f"got {never_page['EventIntegrationAssociations']!r}"
    )
    assert "NextToken" not in never_page, (
        f"expected no NextToken for never-created {never_created_name!r}, "
        f"got {never_page.get('NextToken')!r}"
    )

    def _shape(page):
        return page["EventIntegrationAssociations"], "NextToken" in page

    assert _shape(live_page) == _shape(deleted_page) == _shape(never_page), (
        f"expected the same (associations, has_next_token) shape for a live, a deleted and a "
        f"never-created name; got live={_shape(live_page)!r} deleted={_shape(deleted_page)!r} "
        f"never-created={_shape(never_page)!r}"
    )

    _NOT_FOUND = ("ResourceNotFoundException", f"Could not find EventIntegration with name: {name}.")
    expect_error(lambda: appi.get_event_integration(Name=name), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
