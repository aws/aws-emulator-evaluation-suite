"""remediation-configuration-and-exception-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remediation-configuration-and-exception-lifecycle"
GROUP = 'remediation'
SERVICES = ['config']


_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "Throttling")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    """Call *fn*, retrying AWS Config throttling with exponential backoff; domain errors re-raise."""
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


def _absent_ok(fn, *codes, busy=()):
    """Run a teardown call: return on the resource's not-found codes, retry every 2 s the codes AWS
    answers while the resource is still in use, and raise anything else."""
    deadline = time.monotonic() + 60
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in codes:
                return
            if code not in busy or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _delete_recorder_quiet(ctx, name):
    cfg = ctx.client("config")
    for call in (cfg.stop_configuration_recorder, cfg.delete_configuration_recorder):
        _absent_ok(
            lambda call=call: _retry_throttled(lambda: call(ConfigurationRecorderName=name)),
            "NoSuchConfigurationRecorderException",
        )


def _delete_rule_quiet(ctx, name):
    _absent_ok(
        lambda: ctx.client("config").delete_config_rule(ConfigRuleName=name),
        "NoSuchConfigRuleException",
        busy=("ResourceInUseException",),
    )


def _delete_role_quiet(ctx, name):
    _absent_ok(lambda: ctx.client("iam").delete_role(RoleName=name), "NoSuchEntity")


def _create_automation_role(ctx, role_name):
    """Create a real, assumable AutomationAssumeRole so PutRemediationConfigurations'
    rejection of an unknown SSM document is isolated to the document -- never confounded
    with a role AWS Config cannot resolve or assume."""
    iam = ctx.client("iam")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ssm.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "behavioral-fidelity-check"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_quiet(ctx, role_name))
    return role_arn


def _put_remediation_when_role_ready(cfg, rule_name, doc_id, role_arn, parameters, timeout_s=90.0, interval_s=5.0):
    """PutRemediationConfigurations, retrying while the just-created IAM role has not yet
    propagated (Config validates AutomationAssumeRole eagerly)."""
    deadline = time.monotonic() + timeout_s
    remediation_configuration = {
        "ConfigRuleName": rule_name,
        "TargetType": "SSM_DOCUMENT",
        "TargetId": doc_id,
        "Parameters": {
            "AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}},
            **parameters,
        },
        "Automatic": False,
    }
    while True:
        try:
            return _retry_throttled(
                lambda: cfg.put_remediation_configurations(
                    RemediationConfigurations=[remediation_configuration]
                )
            )
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _reset_recorders(ctx):
    """Remove ANY pre-existing customer-managed configuration recorder (a singleton
    per account/region, so ambient state must be cleared for check independence)."""
    cfg = ctx.client("config")
    try:
        existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except Exception:
        return
    for rec in existing:
        name = rec.get("name")
        if name and not rec.get("servicePrincipal"):
            _delete_recorder_quiet(ctx, name)


def _reset_delivery_channels(ctx):
    """Remove ANY pre-existing delivery channel (also a singleton, limit 1)."""
    cfg = ctx.client("config")
    try:
        existing = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    except Exception:
        return
    for chan in existing:
        name = chan.get("name")
        if name:
            try:
                cfg.delete_delivery_channel(DeliveryChannelName=name)
            except Exception:
                pass


def _create_config_service_role(ctx):
    """Create this check's own AWS Config service role (trusts config.amazonaws.com, has
    AWS_ConfigRole attached) and register its teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cfg-recorder-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "behavioral-fidelity-check"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_quiet(ctx, role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _absent_ok(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            "NoSuchEntity",
        )
    )
    return role_arn


def _ensure_recorder(ctx, rec_name, role_arn=None):
    """Create this check's recorder, first clearing any leaked singleton recorder."""
    cfg = ctx.client("config")
    _reset_recorders(ctx)
    _reset_delivery_channels(ctx)
    if role_arn is None:
        role_arn = _create_config_service_role(ctx)
    recorder = {
        "name": rec_name,
        "roleARN": role_arn,
        "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
    }
    # AWS Config checks that it can assume the role; retry while the new role propagates.
    deadline = time.monotonic() + 90
    while True:
        try:
            _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder))
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "InvalidRoleException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_recorder_quiet(ctx, rec_name))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutRemediationConfigurations rejects a nonexistent SSM document (with a real, assumable role) and
    persists nothing, while an AWS-owned document is accepted; the remediation and exception delete
    and describe paths return exact not-found errors."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    rec_name = ctx.unique_name("sim2real-behav-cfg-rec-")
    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    role_name = ctx.unique_name("sim2real-behav-cfg-remediation-role-")

    _ensure_recorder(ctx, rec_name)
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"},
        }
    )
    ctx.on_cleanup(lambda: _delete_rule_quiet(ctx, rule_name))
    role_arn = _create_automation_role(ctx, role_name)

    # a rule with no remediation yet must report an empty list, not an error
    empty = cfg.describe_remediation_configurations(ConfigRuleNames=[rule_name])[
        "RemediationConfigurations"
    ]
    assert empty == [], f"expected no remediation configuration yet: {empty}"

    # positive control: the wiring (recorder, rule, a real assumable role) is otherwise
    # healthy -- an AWS-owned SSM document IS accepted and persisted through this same role.
    # AWS-PublishSNSNotification is resource-type-agnostic (it notifies rather than acts on
    # the flagged resource), so it is a valid target for a rule of any SourceIdentifier --
    # unlike a resource-scoped document such as AWS-UpdateSSMAgent (EC2-only), which real AWS
    # rejects here with "The remediation target is not valid for <rule>."
    good_doc = "AWS-PublishSNSNotification"
    _put_remediation_when_role_ready(
        cfg,
        rule_name,
        good_doc,
        role_arn,
        {
            "Message": {"StaticValue": {"Values": ["sim2real-behav-fidelity-check"]}},
            "TopicArn": {
                "StaticValue": {
                    "Values": [f"arn:aws:sns:{ctx.region}:{ctx.client('sts').get_caller_identity()['Account']}:sim2real-behav-fidelity-check"]
                }
            },
        },
    )
    described = cfg.describe_remediation_configurations(ConfigRuleNames=[rule_name])[
        "RemediationConfigurations"
    ]
    assert (
        len(described) == 1 and described[0]["TargetId"] == good_doc
    ), f"positive control failed to persist a valid remediation configuration: {described}"
    cfg.delete_remediation_configuration(ConfigRuleName=rule_name)
    restored = cfg.describe_remediation_configurations(ConfigRuleNames=[rule_name])[
        "RemediationConfigurations"
    ]
    assert restored == [], f"positive control cleanup failed to clear state: {restored}"

    # Same rule, same real assumable role: an unknown SSM automation document must be
    # rejected outright, never stored as a dangling remediation target.
    code, message = _error(
        lambda: cfg.put_remediation_configurations(
            RemediationConfigurations=[
                {
                    "ConfigRuleName": rule_name,
                    "TargetType": "SSM_DOCUMENT",
                    "TargetId": "sim2real-behav-NoSuchAutomationDocument",
                    "Parameters": {
                        "AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}},
                    },
                    "Automatic": False,
                }
            ]
        )
    )
    assert code == "InvalidParameterValueException", f"unexpected code: {code}"
    expected = (
        f"The remediation target for {rule_name} could not be found. "
        "Specify the appropriate remediation target and try again."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # nothing may have been persisted by the rejected call
    still_empty = cfg.describe_remediation_configurations(ConfigRuleNames=[rule_name])[
        "RemediationConfigurations"
    ]
    assert still_empty == [], f"a rejected Put must not persist anything: {still_empty}"

    # deleting a remediation configuration that never existed is a hard not-found
    del_code, del_message = _error(
        lambda: cfg.delete_remediation_configuration(ConfigRuleName=rule_name)
    )
    assert del_code == "NoSuchRemediationConfigurationException", f"unexpected code: {del_code}"
    expected = f"No RemediationConfiguration for rule {rule_name} exists"
    assert del_message == expected, f"expected {expected!r}, got {del_message!r}"

    # Remediation EXCEPTIONS are keyed off the rule; with no remediation
    # configuration they must not silently succeed.
    resource_keys = [
        {"ResourceType": "AWS::S3::Bucket", "ResourceId": "sim2real-behav-nonexistent-bucket"}
    ]
    put_exc_code, put_exc_message = _error(
        lambda: cfg.put_remediation_exceptions(
            ConfigRuleName=rule_name, ResourceKeys=resource_keys
        )
    )
    assert put_exc_code == "InvalidParameterValueException", (
        f"unexpected code for PutRemediationExceptions with no remediation: {put_exc_code}"
    )
    expected = f"No RemediationConfiguration found for {rule_name}"
    assert put_exc_message == expected, f"expected {expected!r}, got {put_exc_message!r}"

    # the read path is an exact refusal: with no remediation configuration there is no
    # exception list to read
    no_config_message = "No Remediation Configuration found for exception"
    ec, em = _error(lambda: cfg.describe_remediation_exceptions(ConfigRuleName=rule_name))
    assert ec == "InvalidParameterValueException", f"unexpected code: {ec}"
    assert em == no_config_message, f"expected {no_config_message!r}, got {em!r}"

    # and the delete path refuses the unmatched key with an exact not-found
    ec, em = _error(
        lambda: cfg.delete_remediation_exceptions(
            ConfigRuleName=rule_name, ResourceKeys=resource_keys
        )
    )
    assert ec == "NoSuchRemediationExceptionException", f"unexpected code: {ec}"
    assert em == "Specified RemediationException could not be found.", em

    # terminal read is independent of the mutating delete above: the delete never had
    # anything to remove, so a fresh describe refuses exactly as before.
    ec, em = _error(lambda: cfg.describe_remediation_exceptions(ConfigRuleName=rule_name))
    assert ec == "InvalidParameterValueException", f"unexpected code: {ec}"
    assert em == no_config_message, f"expected {no_config_message!r}, got {em!r}"


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
