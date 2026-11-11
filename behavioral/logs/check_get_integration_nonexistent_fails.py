"""get-integration-nonexistent-fails."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-integration-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIntegration on an integration name that does not exist raises
    ResourceNotFoundException."""
    logs = ctx.client("logs")

    missing_integration_name = ctx.unique_name("sim2real-behav-nosuchintg-")

    code, message = _error(
        lambda: logs.get_integration(integrationName=missing_integration_name)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for GetIntegration on an unknown "
        f"integration name, got {code}"
    )
    expected_message = f"Integration with name {missing_integration_name} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
