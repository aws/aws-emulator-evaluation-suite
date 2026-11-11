"""associate-disassociate-resource-types."""

from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_ROLE_ARN_CACHE = None

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _absent_ok(fn, gone_code):
    """Cleanup step: run fn(); only the not-found code for a resource the check already
    deleted is tolerated, every other error propagates."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


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

def _config_slr_arn(ctx):
    """The AWS Config service-linked role's ARN; the check creates it when the account lacks it."""
    iam = ctx.client("iam")
    try:
        return iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")["Role"]["Arn"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "InvalidInput" or "has been taken" not in err.get("Message", ""):
            raise
    return iam.get_role(RoleName="AWSServiceRoleForConfig")["Role"]["Arn"]


def _ensure_config_role(ctx):
    """The role ARN for ConfigurationRecorder.roleARN: the AWS Config service-linked role."""
    global _ROLE_ARN_CACHE
    if not _ROLE_ARN_CACHE:
        _ROLE_ARN_CACHE = _config_slr_arn(ctx)
    return _ROLE_ARN_CACHE


def _clear_recorders(ctx):
    cfg = ctx.client("config")
    try:
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except Exception:
        return
    for rec in recs:
        name = rec.get("name")
        try:
            _retry_throttled(lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        except Exception:
            pass
        try:
            _retry_throttled(lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        except Exception:
            pass

def _put_recorder_awaiting_role_propagation(cfg, recorder, tags, deadline_s=60.0):
    # IAM role trust/attachment is eventually consistent; a role created moments
    # ago can still make Config's pass-role validation fail with
    # InvalidRoleException. Retry only that specific error, bounded by
    # deadline_s, and re-raise anything else (including a role that will never
    # become valid) immediately.
    start = time.monotonic()
    delay = 2.0
    while True:
        try:
            return cfg.put_configuration_recorder(ConfigurationRecorder=recorder, Tags=tags)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "InvalidRoleException" or time.monotonic() - start > deadline_s:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 10.0)


def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    tags = [{"Key": "sim2real-behav-check", "Value": CHECK}]
    _retry_throttled(lambda: _put_recorder_awaiting_role_propagation(cfg, recorder, tags))
    ctx.on_cleanup(
        lambda: _absent_ok(
            lambda: _retry_throttled(
                lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
            ),
            "NoSuchConfigurationRecorderException",
        )
    )
    return name

CHECK = "associate-disassociate-resource-types"
GROUP = 'configuration-recorder'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """AssociateResourceTypes/DisassociateResourceTypes change a per-type recorder's resourceTypes list,
    and are rejected with ValidationException on an ALL_SUPPORTED_RESOURCE_TYPES recorder."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)

    all_supported_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, 
        all_supported_name,
        recording_group={"allSupported": True, "includeGlobalResourceTypes": False},
    )
    recorder_arn = cfg.describe_configuration_recorders(
        ConfigurationRecorderNames=[all_supported_name]
    )["ConfigurationRecorders"][0].get("arn")
    if recorder_arn is None:
        raise AssertionError("emulator does not return recorder ARN required for this API")

    # Config's association APIs have a very low burst limit; retry_throttled absorbs
    # ThrottlingException but re-raises the expected ValidationException.
    code, code_message = _error(
        lambda: _retry_throttled(
            lambda: cfg.associate_resource_types(
                ConfigurationRecorderArn=recorder_arn,
                ResourceTypes=["AWS::EC2::Volume"],
            )
        )
    )
    # Real AWS rejects associating explicit resource types to an
    # ALL_SUPPORTED-strategy recorder with ValidationException.
    assert code == "ValidationException", code
    assert code_message == (
        "The operation failed. configuration recorder may have a recording strategy that "
        "does not permit association or disassociation of resource types."
    ), code_message

    # Effect-absent: the rejected call must not have touched the recorder.
    unchanged = cfg.describe_configuration_recorders(
        ConfigurationRecorderNames=[all_supported_name]
    )["ConfigurationRecorders"][0]
    assert unchanged["recordingGroup"].get("allSupported") is True, unchanged
    assert not unchanged["recordingGroup"].get("resourceTypes"), unchanged

    cfg.delete_configuration_recorder(ConfigurationRecorderName=all_supported_name)

    scoped_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, 
        scoped_name,
        recording_group={
            "allSupported": False,
            "includeGlobalResourceTypes": False,
            "resourceTypes": ["AWS::S3::Bucket"],
        },
    )
    recorder_arn = cfg.describe_configuration_recorders(
        ConfigurationRecorderNames=[scoped_name]
    )["ConfigurationRecorders"][0].get("arn")
    if recorder_arn is None:
        raise AssertionError("emulator does not return recorder ARN required for this API")

    _retry_throttled(
        lambda: cfg.associate_resource_types(
            ConfigurationRecorderArn=recorder_arn, ResourceTypes=["AWS::EC2::Volume"]
        )
    )
    updated = cfg.describe_configuration_recorders(
        ConfigurationRecorderNames=[scoped_name]
    )["ConfigurationRecorders"][0]
    types = set(updated["recordingGroup"]["resourceTypes"])
    assert {"AWS::S3::Bucket", "AWS::EC2::Volume"} <= types, updated

    _retry_throttled(
        lambda: cfg.disassociate_resource_types(
            ConfigurationRecorderArn=recorder_arn, ResourceTypes=["AWS::EC2::Volume"]
        )
    )
    updated = cfg.describe_configuration_recorders(
        ConfigurationRecorderNames=[scoped_name]
    )["ConfigurationRecorders"][0]
    types = set(updated["recordingGroup"]["resourceTypes"])
    assert "AWS::EC2::Volume" not in types and "AWS::S3::Bucket" in types, updated


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
