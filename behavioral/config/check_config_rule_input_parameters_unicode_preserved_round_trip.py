"""config-rule-input-parameters-unicode-preserved-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "config-rule-input-parameters-unicode-preserved-round-trip"
GROUP = "representation"
SERVICES = ["config"]

_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_MGMT_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """The InputParameters JSON string (containing unicode keys/values) supplied on PutConfigRule
    for a managed rule is returned byte-identical by DescribeConfigRules.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _ensure_configuration_recorder_exists(ctx)

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    input_parameters = {
        "tag1Key": "标签键-Ünïcödé-★",
        "tag1Value": "值-emoji-😀🚀-Ω≈ç√∫˜µ≤≥÷",
    }
    input_parameters_json = json.dumps(input_parameters, ensure_ascii=False)

    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Description": "sim2real behavioral fidelity check: managed rule InputParameters",
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "REQUIRED_TAGS",
            },
            "InputParameters": input_parameters_json,
        },
        Tags=_MGMT_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_config_rule(cfg, rule_name))

    def _describe_probe() -> list[dict[str, Any]]:
        return cfg.describe_config_rules(ConfigRuleNames=[rule_name]).get("ConfigRules", [])

    rules = _poll_until(_describe_probe, lambda rules: len(rules) > 0)
    got_json = rules[0]["InputParameters"]
    assert json.loads(got_json) == input_parameters, (
        f"InputParameters round-trip mismatch: sent {input_parameters!r}, got {json.loads(got_json)!r}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _delete_config_rule(cfg: Any, rule_name: str, timeout_s: float = 60.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfg.delete_config_rule(ConfigRuleName=rule_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _retry_until_role_usable(fn: Callable[[], None], timeout_s: float = 90.0, interval_s: float = 5.0) -> None:
    """IAM roles are eventually consistent; retry the dependent Config call
    until the freshly created role becomes usable, polling the real error
    condition rather than sleeping a fixed duration."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidRoleException", "InsufficientPermissionsException"):
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never became usable within {timeout_s}s: {last_err}")


def _ensure_configuration_recorder_exists(ctx) -> None:
    """PutConfigRule requires at least one configuration recorder to exist in
    the account/region (NoAvailableConfigurationRecorderException otherwise).
    Reuse an existing recorder if present; otherwise create a minimal one
    (role + recorder, deliberately NOT started, no delivery channel, no S3
    bucket) and register its teardown."""
    cfg = ctx.client("config")
    iam = ctx.client("iam")

    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        return

    role_name = ctx.unique_name("sim2real-cfgrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_MGMT_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_MANAGED_POLICY_ARN))

    recorder_name = ctx.unique_name("sim2real-recorder-")

    def _create_recorder() -> None:
        cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": recorder_name,
                "roleARN": role_arn,
                "recordingGroup": {
                    "allSupported": False,
                    "includeGlobalResourceTypes": False,
                    "resourceTypes": ["AWS::CloudTrail::Trail"],
                },
            },
            Tags=_MGMT_TAGS,
        )

    _retry_until_role_usable(_create_recorder)
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
