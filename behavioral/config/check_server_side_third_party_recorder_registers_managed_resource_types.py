"""server-side-third-party-recorder-registers-managed-resource-types."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-third-party-recorder-registers-managed-resource-types"
GROUP = "server-side"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """PutServiceLinkedConfigurationRecorder rejects a valid-looking but unsupported ServicePrincipal
    with ValidationException and the exact message, and registers no recorder for that principal."""
    config = ctx.client("config")
    principal = "not-a-real-integration.amazonaws.com"

    code = None
    message = None
    try:
        config.put_service_linked_configuration_recorder(
            ServicePrincipal=principal,
        )
    except ClientError as exc:
        code = _error_code(exc)
        message = _error_message(exc)

    assert code is not None, (
        "expected an unsupported ServicePrincipal to be rejected, but "
        "PutServiceLinkedConfigurationRecorder succeeded"
    )
    assert code == "ValidationException", (
        f"expected PutServiceLinkedConfigurationRecorder with an unsupported ServicePrincipal to "
        f"raise ValidationException, got {code!r} ({message!r})"
    )
    # Tight enough to separate "not a recognized service principal" from a generic malformed
    # request or a permissions denial -- both raise ValidationException/InsufficientPermissionsException
    # for unrelated reasons on this operation.
    expected_message = (
        "The service principal of the configuration recorder you entered cannot be found. "
        "Verify the configuration recorder service principal, and try again."
    )
    assert message == expected_message, (
        f"expected the unrecognized-service-principal message {expected_message!r}, got {message!r}"
    )

    # The rejection must be a genuine no-op: no recorder was registered for the principal. Only
    # that principal is graded, never the account's other recorders.
    listed = [
        r for r in config.list_configuration_recorders()["ConfigurationRecorderSummaries"]
        if r.get("servicePrincipal") == principal
    ]
    assert listed == [], (
        f"ListConfigurationRecorders shows a recorder for the rejected principal: {listed!r}"
    )
    described = [
        r for r in config.describe_configuration_recorders()["ConfigurationRecorders"]
        if r.get("servicePrincipal") == principal
    ]
    assert described == [], (
        f"DescribeConfigurationRecorders shows a recorder for the rejected principal: {described!r}"
    )



def _error_code(exc: ClientError):
    return exc.response["Error"]["Code"]


def _error_message(exc: ClientError):
    return exc.response["Error"].get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

