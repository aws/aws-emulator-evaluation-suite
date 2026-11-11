"""config-rule-requires-recorder."""

from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last

_RECORDER_FIELDS = ("name", "roleARN", "recordingGroup", "recordingMode")


def _clear_recorders(ctx):
    """Delete every customer-managed recorder; cleanup restores each one and its recording state.

    Returns the names deleted.
    """
    cfg = ctx.client("config")
    recording = {
        st["name"]: st.get("recording", False)
        for st in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    }
    deleted = []
    for rec in cfg.describe_configuration_recorders().get("ConfigurationRecorders", []):
        if rec.get("servicePrincipal"):
            continue
        name = rec["name"]
        snapshot = {k: rec[k] for k in _RECORDER_FIELDS if k in rec}
        was_recording = recording.get(name, False)

        def _restore(snapshot=snapshot, was_recording=was_recording):
            _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=snapshot))
            if was_recording:
                _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=snapshot["name"]))

        if was_recording:
            _retry_throttled(lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        _retry_throttled(lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        ctx.on_cleanup(_restore)
        deleted.append(name)
    return deleted

CHECK = "config-rule-requires-recorder"
GROUP = 'config-rule'
SERVICES = ['config']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutConfigRule is ordered AFTER recorder creation: with no configuration
    recorder in the account it must fail with
    NoAvailableConfigurationRecorderException and persist nothing."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    deleted = _clear_recorders(ctx)
    remaining = [
        r["name"] for r in cfg.describe_configuration_recorders()["ConfigurationRecorders"] if r["name"] in deleted
    ]
    assert remaining == [], remaining

    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    code, message = _error(
        lambda: cfg.put_config_rule(
            ConfigRule={"ConfigRuleName": rule_name, "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"}}
        )
    )
    assert code == "NoAvailableConfigurationRecorderException", code
    assert message == "You must create a configuration recorder before you can create or update a Config rule.", message

    missing, missing_message = _error(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name])
    )
    assert missing == "NoSuchConfigRuleException", missing
    assert missing_message == (
        "One or more ConfigRules provided in the request are invalid. Please check the configRule names."
    ), missing_message


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
