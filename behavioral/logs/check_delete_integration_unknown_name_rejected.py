"""delete-integration-unknown-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-integration-unknown-name-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-integration")
def run(ctx) -> None:
    """GetIntegration and DeleteIntegration on a never-created integrationName raise ResourceNotFoundException
    with its exact message, and ListIntegrations does not list the name."""
    logs = ctx.client("logs")
    bogus_name = ctx.unique_name("sim2real-cwl-integ-missing-")

    get_code, get_message = _error(lambda: logs.get_integration(integrationName=bogus_name))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetIntegration on an unknown name, got {get_code!r}"
    )
    expected_message = f"Integration with name {bogus_name} does not exist."
    assert get_message == expected_message, (
        f"expected message {expected_message!r}, got {get_message!r}"
    )

    delete_code, delete_message = _error(lambda: logs.delete_integration(integrationName=bogus_name))
    assert delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DeleteIntegration on an unknown name, got {delete_code!r}"
    )
    expected_message = f"Integration with name {bogus_name} does not exist."
    assert delete_message == expected_message, (
        f"expected message {expected_message!r}, got {delete_message!r}"
    )

    listed = logs.list_integrations().get("integrationSummaries", [])
    assert not any(s["integrationName"] == bogus_name for s in listed), (
        "an integration that was never created appeared in ListIntegrations"
    )


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
