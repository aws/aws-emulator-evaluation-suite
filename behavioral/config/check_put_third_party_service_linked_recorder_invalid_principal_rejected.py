"""put-third-party-service-linked-recorder-invalid-principal-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-third-party-service-linked-recorder-invalid-principal-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed ServicePrincipal is rejected with the pattern ValidationException before any
    connector lookup, distinct by message from the unrecognized-principal rejection; no recorder.
    """
    # A real connector needs live Azure credentials, so a nonexistent ConnectorArn is used.
    config = ctx.client("config")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = config.meta.region_name
    connector_arn = f"arn:aws:config:{region}:{account_id}:connector/{uuid.uuid4()}"

    # Positive control: a well-formed but unrecognized ServicePrincipal is also
    # rejected with ValidationException, but for the unrecognized-principal reason,
    # not the pattern-shape one -- proving the two are distinguishable.
    control_arn = f"arn:aws:config:{region}:{account_id}:connector/{uuid.uuid4()}"
    control_code, control_message = _error_code_and_message(
        lambda: config.put_third_party_service_linked_configuration_recorder(
            ServicePrincipal="ssm.amazonaws.com",
            ConnectorArn=control_arn,
            ScopeConfiguration={"scopeType": "subscription", "allRegions": True},
        )
    )
    assert control_code == "ValidationException", (
        f"expected the well-formed-but-unrecognized control principal to also be "
        f"rejected with ValidationException, got {control_code!r} ({control_message!r})"
    )
    expected_control = (
        "The service principal of the configuration recorder you entered cannot be found. "
        "Verify the configuration recorder service principal, and try again."
    )
    assert control_message == expected_control, (
        f"expected the control rejection to be the unrecognized-principal message "
        f"{expected_control!r}, got {control_message!r}"
    )

    # Break exactly one thing: a ServicePrincipal that violates the required
    # ^[\\w+=,.@-]+$ pattern (contains a space and an exclamation mark).
    malformed_principal = "not a valid principal!"

    code, message = _error_code_and_message(
        lambda: config.put_third_party_service_linked_configuration_recorder(
            ServicePrincipal=malformed_principal,
            ConnectorArn=connector_arn,
            ScopeConfiguration={"scopeType": "subscription", "allRegions": True},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    expected_pattern = (
        "1 validation error detected: Value at 'servicePrincipal' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]+"
    )
    assert message == expected_pattern, (
        f"expected the pattern-shape validation message {expected_pattern!r}, distinct "
        f"from the control's unrecognized-principal message, got {message!r}"
    )

    # The effect is absent: no service-linked recorder was created for the
    # (nonexistent) connector, and the control plane itself is otherwise reachable.
    recorders = config.list_configuration_recorders().get("ConfigurationRecorderSummaries", [])
    assert not any(r.get("arn") == connector_arn for r in recorders), (
        f"expected no recorder for {connector_arn!r}, but found one in "
        f"{[r.get('arn') for r in recorders]!r}"
    )


def _error_code_and_message(fn):
    """Return (code, message) of fn()'s ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
