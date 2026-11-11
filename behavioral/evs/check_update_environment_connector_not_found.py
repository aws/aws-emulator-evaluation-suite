"""update-environment-connector-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-environment-connector-not-found"
GROUP = "errors"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateEnvironmentConnector on a well-formed but nonexistent environment and connector
    raises ResourceNotFoundException with the message Environment env-0000000000 was not
    found."""
    evs = ctx.client("evs")
    evs.list_environments()

    error = _error(
        lambda: evs.update_environment_connector(
            environmentId="env-0000000000",
            connectorId="cnctr-0000000000",
        )
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        "expected ResourceNotFoundException for a nonexistent environment/connector "
        f"pair, got {error!r}"
    )
    assert error.get("Message") == "Environment env-0000000000 was not found", (
        f"unexpected message {error.get('Message')!r}"
    )


def _error(fn):
    """Call fn() and return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
