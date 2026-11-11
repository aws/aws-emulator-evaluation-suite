"""delete-service-linked-recorder-while-recording-conflict-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-service-linked-recorder-while-recording-conflict-blocked"
GROUP = "error-semantics"
SERVICES = ["config"]

# A principal Config accepts for a customer-created service-linked recorder;
# securityhub.amazonaws.com is rejected with ValidationException.
_SERVICE_PRINCIPAL = "observabilityadmin.amazonaws.com"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """DeleteConfigurationRecorder on a recording service-linked recorder is refused with
    UnmodifiableEntityException naming DeleteServiceLinkedConfigurationRecorder; the recorder
    survives, and only the service-linked delete removes it."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")

    arn, name = _ensure_service_linked_recorder(ctx, config)

    # Precondition: the recorder is live. A service-linked recorder is always recording --
    # that is exactly why the customer delete below cannot be allowed to apply to it.
    status = _recorder_status(config, name)
    assert status.get("recording") is True, (
        f"expected the service-linked recorder to be recording before the blocked delete, "
        f"got status {status!r}"
    )
    assert status.get("servicePrincipal") == _SERVICE_PRINCIPAL, (
        f"expected servicePrincipal {_SERVICE_PRINCIPAL!r} on the recorder status, "
        f"got {status.get('servicePrincipal')!r}"
    )

    # Break exactly one thing: reach for the ordinary customer delete instead of the
    # service-linked one.
    code, message = _error(
        lambda: config.delete_configuration_recorder(ConfigurationRecorderName=name)
    )
    assert code == "UnmodifiableEntityException", (
        f"expected UnmodifiableEntityException deleting a recording service-linked "
        f"recorder through the customer DeleteConfigurationRecorder API, got {code!r} "
        f"({message!r})"
    )
    expected = (
        "DeleteConfigurationRecorder operation does not apply to a service-linked configuration "
        f"recorder {name}. The request was rejected because service-linked configuration recorders "
        "are protected AWS resources. Please use DeleteServiceLinkedConfigurationRecorder API to "
        "attempt the deletion."
    )
    assert message == expected, (
        f"expected the rejection to name the DeleteServiceLinkedConfigurationRecorder API "
        f"as the sanctioned path ({expected!r}), got {message!r}"
    )

    # The effect is absent: the recorder still exists, by its ARN, and is still recording.
    described = config.describe_configuration_recorders(Arn=arn)["ConfigurationRecorders"]
    assert [r["arn"] for r in described] == [arn], (
        f"recorder {arn!r} did not survive the rejected delete: {described!r}"
    )
    assert _recorder_status(config, name).get("recording") is True, (
        "the rejected customer delete stopped the service-linked recorder"
    )

    # Positive control: the sanctioned delete really does remove it, so the rejection
    # above is specific to the customer API and not a recorder that cannot be deleted.
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


def _error(fn):
    """Call fn(); return (error code, message), raising if the call unexpectedly succeeds."""
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


def _restore_config_recorder_on_teardown(ctx) -> None:
    """The Config recorder and delivery channel exist once per account and Region: read them now
    and, in a teardown that runs after the check's own, put back exactly what was there."""
    import time

    from botocore.exceptions import ClientError

    cfg = ctx.client("config")

    def _call(fn):
        deadline = time.monotonic() + 60.0
        while True:
            try:
                return fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() > deadline:
                    raise
                time.sleep(2.0)

    def _recorders():
        found = _call(cfg.describe_configuration_recorders)["ConfigurationRecorders"]
        return [r for r in found if not r.get("servicePrincipal")]

    recorders = _recorders()
    statuses = _call(cfg.describe_configuration_recorder_status)["ConfigurationRecordersStatus"]
    recording = {s["name"] for s in statuses if s.get("recording")}
    channels = _call(cfg.describe_delivery_channels)["DeliveryChannels"]
    fields = ("name", "roleARN", "recordingGroup", "recordingMode")

    def _restore() -> None:
        now = _recorders()
        for r in now:
            _call(lambda n=r["name"]: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        kept = {c["name"] for c in channels}
        for c in _call(cfg.describe_delivery_channels)["DeliveryChannels"]:
            if c["name"] not in kept:
                _call(lambda n=c["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
        kept = {r["name"] for r in recorders}
        for r in now:
            if r["name"] not in kept:
                _call(lambda n=r["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        for r in recorders:
            body = {k: v for k, v in r.items() if k in fields}
            _call(lambda b=body: cfg.put_configuration_recorder(ConfigurationRecorder=b))
        for c in channels:
            _call(lambda c=c: cfg.put_delivery_channel(DeliveryChannel=c))
        for r in recorders:
            if r["name"] in recording:
                _call(lambda n=r["name"]: cfg.start_configuration_recorder(ConfigurationRecorderName=n))

    ctx.on_cleanup(_restore)



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
