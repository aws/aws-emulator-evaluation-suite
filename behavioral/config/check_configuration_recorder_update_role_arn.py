"""configuration-recorder-update-role-arn."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-recorder-update-role-arn"
GROUP = 'configuration-recorder'
SERVICES = ['config']

# ===== helpers =====

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "Throttling")


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    """Call *fn*, retrying AWS Config throttling with exponential backoff.

    The configuration-recorder APIs are aggressively rate limited and the runner's
    client has very few retries, so a suite that creates a recorder per check WILL
    hit ThrottlingException. Throttling is an infrastructure artifact, not a
    fidelity signal, so it must not fail a check. Domain errors are re-raised.
    """
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


def _reset_recorders(ctx):
    """Remove ANY pre-existing customer-managed configuration recorder.

    The configuration recorder is a singleton per account/region, so a recorder
    leaked by an earlier check (or left behind by a throttled delete) would make
    every later PutConfigurationRecorder fail with
    MaxNumberOfConfigurationRecordersExceededException.
    """
    cfg = ctx.client("config")
    try:
        existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except Exception:
        return
    for rec in existing:
        name = rec.get("name")
        if name and not rec.get("servicePrincipal"):
            _delete_recorder_quiet(ctx, name)


def _delete_recorder_quiet(ctx, name):
    cfg = ctx.client("config")
    for call in (cfg.stop_configuration_recorder, cfg.delete_configuration_recorder):
        try:
            _retry_throttled(lambda call=call: call(ConfigurationRecorderName=name))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchConfigurationRecorderException":
                raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """Calling PutConfigurationRecorder again on the same name updates its mutable fields in place."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cfg-rec-")
    role_arn_1 = f"arn:aws:iam::{account_id}:role/config-role-1"
    role_arn_2 = f"arn:aws:iam::{account_id}:role/config-role-2"

    _reset_recorders(ctx)
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": name,
                "roleARN": role_arn_1,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }
        )
    )
    ctx.on_cleanup(lambda: _delete_recorder_quiet(ctx, name))
    # NOTE: allSupported=False REQUIRES an explicit resourceTypes list --
    # omitting it is rejected with InvalidRecordingGroupException.
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": name,
                "roleARN": role_arn_2,
                "recordingGroup": {
                    "allSupported": False,
                    "includeGlobalResourceTypes": False,
                    "resourceTypes": ["AWS::S3::Bucket"],
                },
            }
        )
    )
    recorder = cfg.describe_configuration_recorders(ConfigurationRecorderNames=[name])[
        "ConfigurationRecorders"
    ][0]
    assert recorder["roleARN"] == role_arn_2, f"role ARN not updated: {recorder}"
    assert recorder["recordingGroup"]["allSupported"] is False, f"recordingGroup not updated: {recorder}"
    assert recorder["recordingGroup"]["resourceTypes"] == ["AWS::S3::Bucket"], recorder


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
