"""conformance-pack-compliance-details-roll-up-to-summary."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conformance-pack-compliance-details-roll-up-to-summary"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """The rule-level PASS/FAIL results from GetConformancePackComplianceDetails roll up
    correctly into GetConformancePackComplianceSummary's overall pack status: a pack with
    one COMPLIANT and one NON_COMPLIANT rule must be reported NON_COMPLIANT overall.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    _ensure_config_recorder_exists(ctx)

    pack_name = ctx.unique_name("sim2realpack")
    # AWS Config appends a shared per-pack suffix to every rule name inside a
    # conformance pack, so the ConfigRuleName given in the template is only a
    # prefix of the name actually deployed; resolve the real names afterwards.
    good_prefix = ctx.unique_name("sim2real-proc-ok-")
    bad_prefix = ctx.unique_name("sim2real-proc-bad-")
    template = (
        "Resources:\n"
        "  ProcessCheckRuleOk:\n"
        "    Properties:\n"
        f"      ConfigRuleName: {good_prefix}\n"
        "      Source:\n"
        "        Owner: AWS\n"
        "        SourceIdentifier: AWS_CONFIG_PROCESS_CHECK\n"
        "    Type: AWS::Config::ConfigRule\n"
        "  ProcessCheckRuleBad:\n"
        "    Properties:\n"
        f"      ConfigRuleName: {bad_prefix}\n"
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
    # The pack reaching CREATE_COMPLETE doesn't guarantee every (suffixed) rule
    # inside it is immediately ACTIVE for evaluation calls, so wait for that
    # separately.
    good_rule = _poll_until(
        lambda: _find_active_rule(cfg, good_prefix),
        lambda n: n is not None,
        timeout_s=120,
        interval_s=3,
    )
    bad_rule = _poll_until(
        lambda: _find_active_rule(cfg, bad_prefix),
        lambda n: n is not None,
        timeout_s=120,
        interval_s=3,
    )

    now = datetime.now(timezone.utc)
    cfg.put_external_evaluation(
        ConfigRuleName=good_rule,
        ExternalEvaluation={
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": account_id,
            "ComplianceType": "COMPLIANT",
            "OrderingTimestamp": now,
        },
    )
    cfg.put_external_evaluation(
        ConfigRuleName=bad_rule,
        ExternalEvaluation={
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": account_id,
            "ComplianceType": "NON_COMPLIANT",
            "OrderingTimestamp": now,
        },
    )

    def _details():
        try:
            return cfg.get_conformance_pack_compliance_details(ConformancePackName=pack_name).get(
                "ConformancePackRuleEvaluationResults", []
            )
        except ClientError:
            return []

    details = _poll_until(_details, lambda r: len(r) == 2, timeout_s=180, interval_s=5)
    by_rule = {
        d["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ConfigRuleName"]: d["ComplianceType"]
        for d in details
    }
    assert by_rule[good_rule] == "COMPLIANT"
    assert by_rule[bad_rule] == "NON_COMPLIANT"

    summary = cfg.get_conformance_pack_compliance_summary(ConformancePackNames=[pack_name])
    summary_entry = next(
        s
        for s in summary["ConformancePackComplianceSummaryList"]
        if s["ConformancePackName"] == pack_name
    )
    # One rule failed, so the pack as a whole must roll up to NON_COMPLIANT even though the
    # other rule is compliant.
    assert summary_entry["ConformancePackComplianceStatus"] == "NON_COMPLIANT"


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
    """A conformance pack's ConfigRule needs an ACTIVE (started) recorder, not merely a
    recorder definition: StartConfigurationRecorder itself rejects with
    NoAvailableDeliveryChannelException until a delivery channel exists, and rule
    evaluation needs NoRunningConfigurationRecorderException to not be in play. Adopt
    what already exists; only start/create what is missing, and only clean up what this
    check itself started or created."""
    cfg = ctx.client("config")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    tags = [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}]

    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        recorder_name = existing[0]["name"]
    else:
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
            RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=tags
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
                    Tags=tags,
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

    status = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[recorder_name]
    )["ConfigurationRecordersStatus"][0]
    if status.get("recording"):
        return

    channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    if channels:
        channel_name = channels[0]["name"]
    else:
        account_id = ctx.client("sts").get_caller_identity()["Account"]
        bucket_name = ctx.unique_name("sim2real-cfg-delivery-").lower()
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": ctx.region},
            )
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
        s3.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={"TagSet": tags},
        )
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSConfigBucketPermissionsCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                },
                {
                    "Sid": "AWSConfigBucketDelivery",
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

        channel_name = ctx.unique_name("sim2real-cfg-channel-")
        deadline = time.monotonic() + 60
        last_err = None
        while time.monotonic() < deadline:
            try:
                cfg.put_delivery_channel(
                    DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}
                )
                last_err = None
                break
            except ClientError as e:
                if e.response["Error"]["Code"] in (
                    "InsufficientDeliveryPolicyException",
                    "NoSuchBucketException",
                ):
                    last_err = e
                    time.sleep(3)
                    continue
                raise
        if last_err is not None:
            raise last_err
        ctx.on_cleanup(lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel_name))

    cfg.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name))


def _empty_and_delete_bucket(s3, bucket_name):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


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
