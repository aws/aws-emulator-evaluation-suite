"""delete-service-linked-recorder-conflict-while-active-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-service-linked-recorder-conflict-while-active-blocked"
GROUP = "error-semantics"
SERVICES = ["config"]

# The service principal AWS Config actually accepts for a customer-created service-linked
# configuration recorder. PutServiceLinkedConfigurationRecorder(ServicePrincipal=
# "securityhub.amazonaws.com") is rejected with ValidationException: "The service principal of
# the configuration recorder you entered cannot be found. Verify the configuration recorder
# service principal, and try again."
_SERVICE_PRINCIPAL = "observabilityadmin.amazonaws.com"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:config-recorder", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """An active service-linked configuration recorder cannot be stopped through the customer APIs:
    StopConfigurationRecorder is refused with UnmodifiableEntityException ("always recording"),
    the recorder keeps recording, and DeleteServiceLinkedConfigurationRecorder then succeeds."""
    config = ctx.client("config")

    arn, name = _ensure_service_linked_recorder(ctx, config)

    # Precondition: the recorder is active.
    status = _recorder_status(config, name)
    assert status.get("recording") is True, (
        f"expected the service-linked recorder to be active before the blocked stop, "
        f"got status {status!r}"
    )

    # Break exactly one thing: try to deactivate it the way a customer-managed recorder
    # would be deactivated before deletion.
    code, message = _error(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=name))
    assert code == "UnmodifiableEntityException", (
        f"expected UnmodifiableEntityException stopping an active service-linked recorder, "
        f"got {code!r} ({message!r})"
    )
    expected = (
        "StopConfigurationRecorder operation does not apply to a service-linked configuration "
        f"recorder {name} because it's always recording"
    )
    assert message == expected, (
        f"expected the rejection to explain that a service-linked recorder is always "
        f"recording ({expected!r}), got {message!r}"
    )

    # The effect is absent: it is still recording, not stopped or half-stopped.
    assert _recorder_status(config, name).get("recording") is True, (
        "the rejected StopConfigurationRecorder took effect anyway: the recorder stopped"
    )

    # The same immutability holds in the other direction -- the run state is not
    # customer-settable at all, rather than merely being stuck 'on'.
    start_code, start_message = _error(
        lambda: config.start_configuration_recorder(ConfigurationRecorderName=name)
    )
    assert start_code == "UnmodifiableEntityException", (
        f"expected UnmodifiableEntityException starting an active service-linked recorder, "
        f"got {start_code!r} ({start_message!r})"
    )
    expected_start = (
        "StartConfigurationRecorder operation does not apply to a service-linked configuration "
        f"recorder {name} because it's always recording"
    )
    assert start_message == expected_start, f"start message {start_message!r}, expected {expected_start!r}"

    # Positive control: the sanctioned retirement path works, so the rejections above are
    # about who may change the run state, not a recorder nothing can touch.
    config.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    gone, gone_message = _error(lambda: config.describe_configuration_recorders(Arn=arn))
    assert gone == "NoSuchConfigurationRecorderException", (
        f"expected NoSuchConfigurationRecorderException after the service-linked delete, "
        f"got {gone!r}"
    )
    expected_gone = (
        "The arn of the configuration recorder you entered cannot be found. Verify the configuration "
        "recorder arn, and try again. "
    )
    assert gone_message == expected_gone, f"lookup message {gone_message!r}, expected {expected_gone!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return (error code, message). An unexpected SUCCESS raises, because a
    target that ACCEPTS a call real AWS refuses is the strongest signal available and must
    not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _ensure_service_linked_recorder(ctx, config):
    """Create the service-linked recorder for _SERVICE_PRINCIPAL and return (arn, name).

    An existing recorder is reused: Config allows exactly one recorder per service principal,
    so a second create is a ConflictException.
    """
    try:
        created = config.put_service_linked_configuration_recorder(
            ServicePrincipal=_SERVICE_PRINCIPAL
        )
        arn, name = created["Arn"], created["Name"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConflictException":
            raise
        existing = _find_recorder(config, _SERVICE_PRINCIPAL)
        assert existing is not None, (
            "PutServiceLinkedConfigurationRecorder reported ConflictException for "
            f"{_SERVICE_PRINCIPAL!r} but no such recorder is listed"
        )
        arn, name = existing["arn"], existing["name"]

    ctx.on_cleanup(lambda: _safe(lambda: config.delete_service_linked_configuration_recorder(Arn=arn)))
    return arn, name


def _find_recorder(config, principal):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = config.list_configuration_recorders(**kwargs)
        for summary in page.get("ConfigurationRecorderSummaries", []):
            if summary.get("servicePrincipal") == principal:
                return summary
        next_token = page.get("NextToken")
        if not next_token:
            return None


def _recorder_status(config, name):
    statuses = config.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[name]
    )["ConfigurationRecordersStatus"]
    assert statuses, f"DescribeConfigurationRecorderStatus returned nothing for {name!r}"
    return statuses[0]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchConfigurationRecorderException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
