"""third-party-service-linked-recorder-creation-validation."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "third-party-service-linked-recorder-creation-validation"
GROUP = "state-machine"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutThirdPartyServiceLinkedConfigurationRecorder fails with ValidationException and the pattern
    message for a malformed ServicePrincipal and with a distinct "cannot be found" message for an
    unregistered one, and creates no recorder for the connector ARN."""
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fake_connector_arn = f"arn:aws:config:{ctx.region}:{account_id}:connector/does-not-exist-{uuid.uuid4()}"

    malformed_principal = "not a valid principal!!"  # violates ^[\w+=,.@-]+$

    code, message = _error_code_and_message(
        lambda: config.put_third_party_service_linked_configuration_recorder(
            ServicePrincipal=malformed_principal,
            ConnectorArn=fake_connector_arn,
            ScopeConfiguration={"scopeType": "subscription", "allRegions": True},
        )
    )
    assert code == "ValidationException", code
    expected_message = (
        "1 validation error detected: Value at 'servicePrincipal' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: [\w+=,.@-]+"
    )
    assert message == expected_message, message

    # Distinguishing control: a syntactically valid but unregistered principal
    # against the same (still nonexistent) connector ARN also fails with
    # ValidationException, but for a different reason -- proving the check above
    # is specifically catching the malformed shape, not any-call-to-this-op.
    valid_shaped_principal = "not-a-real-service.amazonaws.com"
    control_code, control_message = _error_code_and_message(
        lambda: config.put_third_party_service_linked_configuration_recorder(
            ServicePrincipal=valid_shaped_principal,
            ConnectorArn=fake_connector_arn,
            ScopeConfiguration={"scopeType": "subscription", "allRegions": True},
        )
    )
    assert control_code == "ValidationException", control_code
    expected_control_message = (
        "The service principal of the configuration recorder you entered cannot be "
        "found. Verify the configuration recorder service principal, and try again."
    )
    assert control_message == expected_control_message, control_message
    assert control_message != message, (
        f"expected the malformed-shape message to differ from the "
        f"unregistered-principal message, got the same text: {message!r}"
    )

    # effect absent: neither malformed nor merely-unregistered attempt created a recorder
    summaries = _list_all_recorders(config)
    leaked = [item for item in summaries if item.get("arn") == fake_connector_arn]
    assert not leaked, f"expected no recorder for {fake_connector_arn!r}, found {leaked!r}"


def _list_all_recorders(config):
    items = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = config.list_configuration_recorders(**kwargs)
        items.extend(resp.get("ConfigurationRecorderSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return items


def _error_code_and_message(fn):
    try:
        fn()
    except Exception as err:  # noqa: BLE001
        response = getattr(err, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message", "")
        raise
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
