"""get-conformance-pack-compliance-details-unknown-rule-filter-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-conformance-pack-compliance-details-unknown-rule-filter-rejected"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """GetConformancePackComplianceDetails rejects a ConfigRuleNames filter that names a
    rule not present in the pack, while filtering by the pack's real rule still succeeds.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    _ensure_config_recorder_exists(ctx)

    pack_name = ctx.unique_name("sim2realpack")
    # AWS Config appends a shared per-pack suffix to every rule name inside a
    # conformance pack, so the ConfigRuleName given in the template is only a
    # prefix of the name actually deployed; resolve the real name afterwards.
    rule_prefix = ctx.unique_name("sim2real-proc-")
    template = (
        "Resources:\n"
        "  ProcessCheckRule:\n"
        "    Properties:\n"
        f"      ConfigRuleName: {rule_prefix}\n"
        "      Source:\n"
        "        Owner: AWS\n"
        "        SourceIdentifier: AWS_CONFIG_PROCESS_CHECK\n"
        "    Type: AWS::Config::ConfigRule\n"
    )
    cfg.put_conformance_pack(
        ConformancePackName=pack_name,
        TemplateBody=template,
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: cfg.delete_conformance_pack(ConformancePackName=pack_name))

    _poll_until(
        lambda: _pack_state(cfg, pack_name),
        lambda s: s == "CREATE_COMPLETE",
        timeout_s=180,
        interval_s=5,
    )
    # The pack reaching CREATE_COMPLETE doesn't guarantee the (suffixed) rule inside
    # it is immediately ACTIVE for evaluation calls, so wait for that separately.
    rule_name = _poll_until(
        lambda: _find_active_rule(cfg, rule_prefix),
        lambda n: n is not None,
        timeout_s=120,
        interval_s=3,
    )

    cfg.put_external_evaluation(
        ConfigRuleName=rule_name,
        ExternalEvaluation={
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": account_id,
            "ComplianceType": "NON_COMPLIANT",
            "OrderingTimestamp": datetime.now(timezone.utc),
        },
    )

    def _details_for(name):
        return cfg.get_conformance_pack_compliance_details(
            ConformancePackName=pack_name, Filters={"ConfigRuleNames": [name]}
        ).get("ConformancePackRuleEvaluationResults", [])

    # Positive control: filtering by the pack's real rule name works and reflects the eval.
    details = _poll_until(lambda: _details_for(rule_name), lambda r: len(r) == 1, timeout_s=180, interval_s=5)
    assert details[0]["ComplianceType"] == "NON_COMPLIANT", (
        f"expected the externally-set eval to read back NON_COMPLIANT, got {details[0]!r}"
    )

    # Negative: filtering by a rule name that is not part of this pack is rejected.
    bogus_rule = ctx.unique_name("sim2real-notinpack-")
    code, message = _error(lambda: _details_for(bogus_rule))
    assert code == "NoSuchConfigRuleInConformancePackException", (
        f"expected NoSuchConfigRuleInConformancePackException for a filter naming a rule "
        f"outside the pack, got {code!r}"
    )
    assert message == f"No rule with name {bogus_rule} exists in conformance pack {pack_name}", message

    # Effect absent: no results were fabricated for the bogus filter (the call raised
    # instead of silently returning an empty/partial page).
    # Positive control still holds after the negative probe.
    details_again = _details_for(rule_name)
    assert len(details_again) == 1, (
        f"expected exactly 1 result for the real rule after the negative probe, got {details_again!r}"
    )
    assert details_again[0]["ComplianceType"] == "NON_COMPLIANT", (
        f"expected the real rule's eval to still read NON_COMPLIANT after the negative probe, "
        f"got {details_again[0]!r}"
    )


def _pack_state(cfg, pack_name):
    details = cfg.describe_conformance_pack_status(
        ConformancePackNames=[pack_name]
    ).get("ConformancePackStatusDetails", [])
    if not details:
        return None
    return details[0]["ConformancePackState"]


def _rule_state(cfg, rule_name):
    try:
        rules = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchConfigRuleException":
            return None
        raise
    if not rules:
        return None
    return rules[0].get("ConfigRuleState")


def _find_active_rule(cfg, name_prefix):
    """AWS Config appends a shared per-pack suffix to every rule name inside a
    conformance pack, so find the actual deployed name by prefix instead of
    guessing the suffix."""
    next_token = None
    for _ in range(50):
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        page = cfg.describe_config_rules(**kwargs)
        for rule in page.get("ConfigRules", []):
            if rule["ConfigRuleName"].startswith(name_prefix) and rule.get("ConfigRuleState") == "ACTIVE":
                return rule["ConfigRuleName"]
        next_token = page.get("NextToken")
        if not next_token:
            break
    return None


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this filter, but it succeeded and returned {result!r}")


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
    resource_tags = [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}]
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
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=resource_tags
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
                Tags=resource_tags,
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
