"""compliance-surfaces-for-config-rule."""

from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_ROLE_ARN_CACHE = None

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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

def _retry_on(fn, error_codes, *, timeout_s=60.0, interval_s=5.0):
    # IAM is eventually consistent; Config's pass-role validation raises
    # InvalidRoleException until a just-created role has propagated.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
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
        lambda: _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder)),
        ("InvalidRoleException",),
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
        )
    )
    return name

CHECK = "compliance-surfaces-for-config-rule"
GROUP = 'compliance'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A freshly created rule reads INSUFFICIENT_DATA with empty evaluation results across the
    compliance surfaces; DeleteEvaluationResults succeeds on it without deleting the rule and is a
    hard not-found (NoSuchConfigRuleException) for a rule that does not exist."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder_name)

    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"},
        }
    )
    ctx.on_cleanup(lambda a=rule_name: cfg.delete_config_rule(ConfigRuleName=a))

    by_rule = cfg.describe_compliance_by_config_rule(ConfigRuleNames=[rule_name])[
        "ComplianceByConfigRules"
    ]
    # Real AWS returns exactly one entry, keyed to this rule, the instant the rule exists —
    # before any evaluation has run its ComplianceType is the documented pre-evaluation state.
    assert len(by_rule) == 1 and by_rule[0]["ConfigRuleName"] == rule_name, by_rule
    assert by_rule[0]["Compliance"]["ComplianceType"] == "INSUFFICIENT_DATA", by_rule

    rule_summary = cfg.get_compliance_summary_by_config_rule()["ComplianceSummary"]
    assert "ComplianceSummaryTimestamp" in rule_summary, rule_summary

    type_summary = cfg.get_compliance_summary_by_resource_type()[
        "ComplianceSummariesByResourceType"
    ]
    assert isinstance(type_summary, list) and len(type_summary) >= 1, type_summary

    details = cfg.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)
    # The recorder is never started, so no configuration item is ever delivered to the rule —
    # the evaluation surface is queryable but deterministically empty, never "some list".
    assert details["EvaluationResults"] == [], details

    by_resource = cfg.describe_compliance_by_resource(ResourceType="AWS::S3::Bucket")
    assert by_resource["ComplianceByResources"] == [], by_resource

    res_details = cfg.get_compliance_details_by_resource(
        ResourceType="AWS::S3::Bucket", ResourceId="sim2real-behav-nonexistent-bucket"
    )
    assert res_details["EvaluationResults"] == [], res_details

    # DeleteEvaluationResults is valid on an existing rule and leaves the rule intact
    cfg.delete_evaluation_results(ConfigRuleName=rule_name)
    still_there = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
    assert len(still_there) == 1, still_there

    # and it must be a hard not-found for a rule that does not exist
    code, code_message = _error(
        lambda: cfg.delete_evaluation_results(ConfigRuleName="sim2real-behav-no-such-rule")
    )
    assert code == "NoSuchConfigRuleException", code
    assert code_message == (
        "The ConfigRule 'sim2real-behav-no-such-rule' provided in the request is invalid. "
        "Please check the configRule name."
    ), code_message


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
