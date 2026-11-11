"""conformance-pack-lifecycle."""

from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_ROLE_ARN_CACHE = None

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
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

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

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

def _retry_on(fn, error_codes, *, timeout_s=60.0, interval_s=5.0):
    # IAM is eventually consistent: a role created moments ago can still be
    # rejected as invalid by Config's pass-role validation. Bound the wait on
    # that specific code instead of guessing a fixed delay.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in error_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    _retry_on(
        lambda: _retry_throttled(
            lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder)
        ),
        ("InvalidRoleException",),
    )
    ctx.on_cleanup(
        lambda: _absent_ok(
            lambda: _retry_throttled(
                lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
            ),
            "NoSuchConfigurationRecorderException",
        )
    )
    return name

CHECK = "conformance-pack-lifecycle"
GROUP = 'conformance-pack'
SERVICES = ['config']

MINIMAL_CONFORMANCE_PACK_TEMPLATE = """Resources:
  ConfigRuleForVersioning:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cfp-s3-versioning-rule
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_VERSIONING_ENABLED
"""

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutConformancePack rejects malformed templates up front; a valid
    template drives CREATE_IN_PROGRESS -> CREATE_COMPLETE, and
    DeleteConformancePack removes it entirely."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder_name)

    bad_name = ctx.unique_name("sim2real-behav-cfg-badpack-")
    code, code_message = _error(
        lambda: cfg.put_conformance_pack(
            ConformancePackName=bad_name,
            TemplateBody="""not: [ valid :: yaml {{""",
        )
    )
    assert code == "ConformancePackTemplateValidationException", code
    assert code_message == "Template passed in the input parameter is invalid", code_message

    # Effect absent: the rejected template must not have left a pack behind
    # for that name -- an independent read, not just the rejecting call's own
    # response.
    bad_names = set()
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = cfg.describe_conformance_packs(**kwargs)
        bad_names.update(p["ConformancePackName"] for p in page.get("ConformancePackDetails", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert bad_name not in bad_names, bad_names

    pack_name = ctx.unique_name("sim2real-behav-cfg-pack-")

    cfg.put_conformance_pack(
        ConformancePackName=pack_name, TemplateBody=MINIMAL_CONFORMANCE_PACK_TEMPLATE
    )
    ctx.on_cleanup(
        lambda a=pack_name: _absent_ok(
            lambda: cfg.delete_conformance_pack(ConformancePackName=a), "NoSuchConformancePackException"
        )
    )

    def _status():
        details = cfg.describe_conformance_pack_status(
            ConformancePackNames=[pack_name]
        )["ConformancePackStatusDetails"]
        return details[0] if details else None

    final = _poll_until(
        _status,
        lambda s: s is not None and s.get("ConformancePackState") in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert final["ConformancePackState"] == "CREATE_COMPLETE", final

    cfg.delete_conformance_pack(ConformancePackName=pack_name)

    # DeleteConformancePack is asynchronous (it tears down a backing CFN stack);
    # on real AWS the pack lingers in DELETE_IN_PROGRESS for ~60-70s before
    # DescribeConformancePacks finally raises NoSuchConformancePackException, so
    # poll well past that.
    def _lookup():
        """The describe response while the resource is still listed, else its Error dict."""
        try:
            return {"Listed": cfg.describe_conformance_packs(ConformancePackNames=[pack_name])}
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err

    gone_err = _poll_until(
        _lookup,
        lambda r: "Listed" not in r,
        timeout_s=180,
        interval_s=5,
    )
    gone, gone_message = gone_err.get("Code"), gone_err.get("Message")
    assert gone == "NoSuchConformancePackException", gone_err
    assert gone_message == (
        f"No such conformance pack exists. Conformance Pack(s): [{pack_name}]"
    ), gone_err


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
