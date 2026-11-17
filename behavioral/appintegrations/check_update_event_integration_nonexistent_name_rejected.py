"""update-event-integration-nonexistent-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-event-integration-nonexistent-name-rejected"
GROUP = "negative-classes"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateEventIntegration on a name that was never created is refused with
    ResourceNotFoundException, and the same call succeeds against a live event integration.
    """
    appi = ctx.client("appintegrations")
    missing_name = ctx.unique_name("sim2real-eiu-missing-")

    _NOT_FOUND = (
        "ResourceNotFoundException",
        f"Could not find EventIntegration with name: {missing_name}.",
    )
    expect_error(lambda: appi.update_event_integration(Name=missing_name, Description="x"), *_NOT_FOUND)

    # positive control: the same call succeeds against a live integration
    live_name = ctx.unique_name("sim2real-eiu-live-")
    appi.create_event_integration(
        Name=live_name,
        Description="before update",
        EventFilter={"Source": "aws.cases"},
        EventBridgeBus="default",
    )

    def _delete() -> None:
        try:
            appi.delete_event_integration(Name=live_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)

    appi.update_event_integration(Name=live_name, Description="after update")
    updated = appi.get_event_integration(Name=live_name)
    assert updated["Description"] == "after update", (
        f"expected Description 'after update' on the positive control, got {updated['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
