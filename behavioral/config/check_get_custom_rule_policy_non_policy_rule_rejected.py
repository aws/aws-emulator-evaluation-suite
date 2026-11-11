"""get-custom-rule-policy-non-policy-rule-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-custom-rule-policy-non-policy-rule-rejected"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """GetCustomRulePolicy rejects a rule that is not a CUSTOM_POLICY rule (a process-check
    rule owned by AWS), while a genuine custom-policy rule's policy text still resolves.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")

    _ensure_config_recorder_exists(ctx)

    policy_text = (
        "rule sim2real_check_tags {\n"
        "    configuration.tags != null\n"
        "}\n"
    )
    policy_rule = ctx.unique_name("sim2real-custompolicy-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": policy_rule,
            "Source": {
                "Owner": "CUSTOM_POLICY",
                "SourceDetails": [
                    {"EventSource": "aws.config", "MessageType": "ConfigurationItemChangeNotification"}
                ],
                "CustomPolicyDetails": {
                    "PolicyRuntime": "guard-2.x.x",
                    "PolicyText": policy_text,
                },
            },
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=policy_rule))

    # Positive control: the genuine custom-policy rule's policy round-trips.
    control = _poll_until(
        lambda: cfg.get_custom_rule_policy(ConfigRuleName=policy_rule).get("PolicyText"),
        lambda p: p is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert control == policy_text, f"expected the custom-policy rule's policy text to round-trip verbatim, got {control!r}"

    # Negative: a real AWS-managed rule (Owner=AWS, non-custom-policy) has no
    # custom-policy details at all. IAM_USER_NO_POLICIES_CHECK takes no required
    # input parameters, so it can be attached directly via PutConfigRule.
    process_rule = ctx.unique_name("sim2real-managed-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": process_rule,
            "Source": {"Owner": "AWS", "SourceIdentifier": "IAM_USER_NO_POLICIES_CHECK"},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=process_rule))

    code, message = _error(lambda: cfg.get_custom_rule_policy(ConfigRuleName=process_rule))
    assert code == "NoSuchConfigRuleException", (
        f"expected GetCustomRulePolicy on a process-check (Owner=AWS) rule to be rejected "
        f"with NoSuchConfigRuleException, got {code!r}"
    )
    assert message == (
        f"The ConfigRule '{process_rule}' provided in the request is invalid. Please check the "
        "configRule name."
    ), message

    # Effect absent: the process-check rule genuinely has no custom-policy details.
    described = cfg.describe_config_rules(ConfigRuleNames=[process_rule])["ConfigRules"][0]
    assert "CustomPolicyDetails" not in described["Source"], (
        f"expected the process-check rule's Source to carry no CustomPolicyDetails, got {described['Source']!r}"
    )

    # Positive control still holds after probing the negative case.
    still_good = cfg.get_custom_rule_policy(ConfigRuleName=policy_rule)["PolicyText"]
    assert still_good == policy_text, (
        f"expected the genuine custom-policy rule's policy text to still round-trip after probing "
        f"the rejected rule, got {still_good!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_config_recorder_exists(ctx) -> None:
    cfg = ctx.client("config")
    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        return
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
    try:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    except ClientError:
        pass

    recorder_name = ctx.unique_name("sim2real-recorder-")
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            cfg.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": False, "resourceTypes": ["AWS::SNS::Topic"]},
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            last_err = None
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException":
                last_err = e
                time.sleep(3)
                continue
            raise
    if last_err is not None:
        raise last_err
    ctx.on_cleanup(lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name))


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
