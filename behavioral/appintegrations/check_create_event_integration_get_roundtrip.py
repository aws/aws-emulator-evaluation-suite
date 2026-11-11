"""create-event-integration-get-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-integration-get-roundtrip"
GROUP = "data-plane"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEventIntegration persists Name/Description/EventFilter/EventBridgeBus, retrievable via
    GetEventIntegration; after DeleteEventIntegration, the same GetEventIntegration call fails with
    ResourceNotFoundException."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-evt-")

    created = appi.create_event_integration(
        Name=name,
        Description="sim2real event integration roundtrip",
        EventFilter={"Source": "aws.cases"},
        EventBridgeBus="default",
        Tags={"sim2real": "appintegrations-behavioral"},
    )
    arn = created["EventIntegrationArn"]

    def _cleanup() -> None:
        try:
            appi.delete_event_integration(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = appi.get_event_integration(Name=name)
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Description"] == "sim2real event integration roundtrip", (
        f"expected persisted Description, got {got['Description']!r}"
    )
    assert got["EventFilter"]["Source"] == "aws.cases", (
        f"expected EventFilter.Source 'aws.cases', got {got['EventFilter']!r}"
    )
    assert got["EventBridgeBus"] == "default", (
        f"expected EventBridgeBus 'default', got {got['EventBridgeBus']!r}"
    )
    assert got["EventIntegrationArn"] == arn, (
        f"expected EventIntegrationArn {arn!r} from create response, got {got['EventIntegrationArn']!r}"
    )

    appi.delete_event_integration(Name=name)
    try:
        appi.get_event_integration(Name=name)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for a deleted event integration, got {code!r}"
        )
        message = err.response["Error"].get("Message")
        expected_message = f"Could not find EventIntegration with name: {name}."
        assert message == expected_message, f"expected {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(
            "expected GetEventIntegration to fail with ResourceNotFoundException after delete, but it succeeded"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
