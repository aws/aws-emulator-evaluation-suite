"""custom-rule-policy-retrieval-matches-put."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-rule-policy-retrieval-matches-put"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """GetCustomRulePolicy returns exactly the Guard policy text supplied when the
    CUSTOM_POLICY config rule was created via PutConfigRule.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")

    _ensure_config_recorder_exists(ctx)

    rule_name = ctx.unique_name("sim2real-custompolicy-")
    policy_text = (
        "rule sim2real_check_tags {\n"
        "    configuration.tags != null\n"
        "}\n"
    )
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))

    retrieved = _poll_until(
        lambda: cfg.get_custom_rule_policy(ConfigRuleName=rule_name).get("PolicyText"),
        lambda p: p is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert retrieved == policy_text, f"expected GetCustomRulePolicy to return the PolicyText supplied on PutConfigRule, got {retrieved!r} != {policy_text!r}"


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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
                }
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
