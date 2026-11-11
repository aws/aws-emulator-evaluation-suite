"""put-external-evaluation-timestamp-preserved."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-external-evaluation-timestamp-preserved"
GROUP = "representation"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """The OrderingTimestamp given to PutExternalEvaluation for a process-check rule comes back
    verbatim in GetComplianceDetailsByConfigRule's EvaluationResultIdentifier: not rounded,
    re-zoned, or replaced with the server's receipt time."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    sts = ctx.client("sts")
    _ensure_config_recorder_exists(ctx)

    # AWS_CONFIG_PROCESS_CHECK rules can only be created as part of a
    # conformance pack (PutConfigRule rejects that SourceIdentifier directly
    # with InvalidParameterValueException), so deploy a minimal conformance
    # pack containing one.
    pack_name = ctx.unique_name("sim2real-pc-pack-")
    rule_name = ctx.unique_name("sim2real-pc-rule-")
    account_id = sts.get_caller_identity()["Account"]


    template_body = f"""Resources:
  Sim2RealProcessCheck:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: {rule_name}
      Description: sim2real behavioral process-check rule
      Source:
        Owner: AWS
        SourceIdentifier: AWS_CONFIG_PROCESS_CHECK
"""
    cfg.put_conformance_pack(ConformancePackName=pack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_conformance_pack_with_retry(cfg, pack_name))

    deadline = time.monotonic() + 300.0
    last_status = None
    while time.monotonic() < deadline:
        statuses = cfg.describe_conformance_pack_status(
            ConformancePackNames=[pack_name]
        )["ConformancePackStatusDetails"]
        last_status = statuses[0]["ConformancePackState"] if statuses else None
        if last_status == "CREATE_COMPLETE":
            break
        if last_status == "CREATE_FAILED":
            reason = statuses[0].get("ConformancePackStatusReason", "") if statuses else ""
            raise AssertionError(f"conformance pack failed to deploy: {reason}")
        time.sleep(5.0)
    else:
        raise AssertionError(
            f"conformance pack {pack_name} never reached CREATE_COMPLETE (last: {last_status})"
        )

    deadline = time.monotonic() + 30.0
    resolved_rule_name = None
    while time.monotonic() < deadline:
        resolved_rule_name = _find_rule_by_prefix(cfg, rule_name)
        if resolved_rule_name is not None:
            rules = cfg.describe_config_rules(ConfigRuleNames=[resolved_rule_name])["ConfigRules"]
            if rules and rules[0]["ConfigRuleState"] == "ACTIVE":
                break
        time.sleep(1.0)
    else:
        raise AssertionError("process-check config rule never became ACTIVE")
    rule_name = resolved_rule_name


    ordering_timestamp = datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ) - datetime.timedelta(minutes=5)

    cfg.put_external_evaluation(
        ConfigRuleName=rule_name,
        ExternalEvaluation={
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": account_id,
            "ComplianceType": "NON_COMPLIANT",
            "Annotation": "sim2real behavioral timestamp check",
            "OrderingTimestamp": ordering_timestamp,
        },
    )

    matches: list[dict[str, Any]] = []
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        results = cfg.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)[
            "EvaluationResults"
        ]
        matches = [
            r
            for r in results
            if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
            == account_id
        ]
        if matches:
            break
        time.sleep(1.5)

    assert matches, "external evaluation never appeared in GetComplianceDetailsByConfigRule"
    recorded_timestamp = matches[0]["EvaluationResultIdentifier"]["OrderingTimestamp"]
    assert recorded_timestamp == ordering_timestamp, (
        f"OrderingTimestamp not preserved verbatim: {recorded_timestamp!r} != {ordering_timestamp!r}"
    )
    assert matches[0]["ComplianceType"] == "NON_COMPLIANT", (
        f"expected NON_COMPLIANT, got {matches[0]['ComplianceType']!r}"
    )


# ===== helpers =====


def _find_rule_by_prefix(cfg, name_prefix: str) -> str | None:
    """Conformance packs may append a random suffix to the ConfigRuleName
    given in the template, so resolve the actual created rule name by
    scanning DescribeConfigRules for one that starts with our requested name."""
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = cfg.describe_config_rules(**kwargs)
        for rule in resp.get("ConfigRules", []):
            if rule["ConfigRuleName"].startswith(name_prefix):
                return rule["ConfigRuleName"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


def _delete_conformance_pack_with_retry(cfg, pack_name: str) -> None:
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cfg.delete_conformance_pack(ConformancePackName=pack_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchConformancePackException":
                return
            if code != "ResourceInUseException" or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _ensure_config_recorder_exists(ctx) -> None:
    """PutConfigRule (including indirectly, via a conformance pack) requires a
    configuration recorder to exist in the account/region
    (NoAvailableConfigurationRecorderException otherwise). Create the minimal
    IAM role / recorder needed if none exists yet, registering cleanup."""
    cfg = ctx.client("config")
    iam = ctx.client("iam")

    existing_recorders = cfg.describe_configuration_recorders().get(
        "ConfigurationRecorders", []
    )
    if existing_recorders:
        return

    role_name = ctx.unique_name("sim2real-config-role-")
    recorder_name = ctx.unique_name("sim2real-config-recorder-")

    trust_policy = json.dumps(
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
        )
    )

    # IAM role trust/permissions can take a few seconds to propagate.
    deadline = time.monotonic() + 30.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            cfg.put_configuration_recorder(
                ConfigurationRecorder={"name": recorder_name, "roleARN": role_arn}
            )
            last_error = None
            break
        except Exception as exc:  # noqa: BLE001 - retry on transient assume-role failure
            last_error = exc
            time.sleep(2.0)
    if last_error is not None:
        raise last_error
    ctx.on_cleanup(
        lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
    )


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
