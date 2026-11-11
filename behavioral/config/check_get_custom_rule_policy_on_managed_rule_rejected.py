"""get-custom-rule-policy-on-managed-rule-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-custom-rule-policy-on-managed-rule-rejected"
GROUP = "representation"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """GetCustomRulePolicy on an AWS-managed rule (no CustomPolicyDetails) is rejected
    with NoSuchConfigRuleException, while the same call against a real Custom Policy
    rule (positive control, same file) succeeds and returns its policy text."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _ensure_config_recorder_exists(ctx)

    # --- positive control: a genuine Custom Policy rule works ---
    policy_rule_name = ctx.unique_name("sim2real-policyrule-")
    policy_text = (
        "rule sim2real_versioning_check when resourceType == \"AWS::S3::Bucket\" {\n"
        "  configuration.versioningConfiguration.status == \"Enabled\"\n"
        "}\n"
    )
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": policy_rule_name,
            "Description": "sim2real positive-control custom policy rule",
            "Source": {
                "Owner": "CUSTOM_POLICY",
                "CustomPolicyDetails": {
                    "PolicyRuntime": "guard-2.x.x",
                    "PolicyText": policy_text,
                    "EnableDebugLogDelivery": False,
                },
                "SourceDetails": [
                    {
                        "EventSource": "aws.config",
                        "MessageType": "ConfigurationItemChangeNotification",
                    }
                ],
            },
            "EvaluationModes": [{"Mode": "DETECTIVE"}],
        }
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=policy_rule_name))
    control_resp = cfg.get_custom_rule_policy(ConfigRuleName=policy_rule_name)
    assert control_resp["PolicyText"] == policy_text, (
        f"positive control PolicyText mismatch: expected {policy_text!r}, "
        f"got {control_resp['PolicyText']!r}"
    )

    # --- break exactly one thing: an AWS-managed rule has no custom policy ---
    managed_rule_name = ctx.unique_name("sim2real-managedrule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": managed_rule_name,
            "Description": "sim2real managed rule (not a custom policy rule)",
            "Source": {"Owner": "AWS", "SourceIdentifier": "IAM_USER_MFA_ENABLED"},
        }
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=managed_rule_name))

    code, message = _error(lambda: cfg.get_custom_rule_policy(ConfigRuleName=managed_rule_name))
    assert code == "NoSuchConfigRuleException", (
        f"expected NoSuchConfigRuleException for GetCustomRulePolicy on a managed rule, got {code!r}"
    )
    assert message == (
        f"The ConfigRule '{managed_rule_name}' provided in the request is invalid. Please check the "
        "configRule name."
    ), message

    # effect absent: the managed rule is still a plain AWS-owned rule, unaffected
    described = cfg.describe_config_rules(ConfigRuleNames=[managed_rule_name])["ConfigRules"][0]
    assert described["Source"]["Owner"] == "AWS", (
        f"expected managed rule Source.Owner == 'AWS', got {described['Source']['Owner']!r}"
    )
    assert "CustomPolicyDetails" not in described["Source"], (
        f"managed rule unexpectedly carries CustomPolicyDetails: {described['Source']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _ensure_config_recorder_exists(ctx) -> bool:
    """Ensure a customer-managed configuration recorder exists (need not be running).
    PutConfigRule requires at least one to exist (NoAvailableConfigurationRecorderException
    otherwise). Returns True if this call created the role+recorder itself."""
    cfg = ctx.client("config")
    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        return False

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfgrole-")
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    def _try_put() -> bool:
        try:
            cfg.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": role_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidRoleException":
                return False
            raise

    _poll_until(_try_put, lambda ok: ok, timeout_s=60.0, interval_s=3.0)
    ctx.on_cleanup(lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=role_name))
    return True


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
