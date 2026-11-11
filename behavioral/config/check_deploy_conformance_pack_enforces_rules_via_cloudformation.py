"""deploy-conformance-pack-enforces-rules-via-cloudformation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-conformance-pack-enforces-rules-via-cloudformation"
GROUP = "deploy"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A conformance pack with one embedded rule reaches CREATE_COMPLETE with that rule ACTIVE, evaluates
    a real resource COMPLIANT in DescribeConformancePackCompliance, and reports COMPLIANT in
    GetConformancePackComplianceSummary."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    s3 = ctx.client("s3")

    recorder_name, created_recorder = _ensure_active_recorder(ctx)

    # A brand-new bucket gets Amazon S3's default SSE-S3 encryption automatically (default bucket
    # encryption has been enabled for all new buckets), so scoping the managed rule to exactly this
    # bucket makes COMPLIANT the one deterministic outcome regardless of anything else already in
    # the account.
    bucket_name = ctx.unique_name("sim2real-cpack-bucket-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))

    _poll_until(
        lambda: config.list_discovered_resources(resourceType="AWS::S3::Bucket", resourceName=bucket_name),
        lambda page: any(r["resourceName"] == bucket_name for r in page.get("resourceIdentifiers", [])),
        timeout_s=240,
        interval_s=10,
    )

    pack_name = ctx.unique_name("sim2real-cpack-")
    rule_name = ctx.unique_name("sim2real-cpack-rule-")
    # Conformance pack TemplateBody only supports YAML for the two allowed
    # resource types (AWS::Config::ConfigRule / RemediationConfiguration) --
    # a JSON document is rejected with ConformancePackTemplateValidationException.
    template = f"""
Resources:
  EncryptionCheck:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: {rule_name}
      Scope:
        ComplianceResourceTypes:
          - AWS::S3::Bucket
        ComplianceResourceId: {bucket_name}
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
"""
    config.put_conformance_pack(ConformancePackName=pack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: config.delete_conformance_pack(ConformancePackName=pack_name))

    detail = _poll_until(
        lambda: config.describe_conformance_pack_status(ConformancePackNames=[pack_name])[
            "ConformancePackStatusDetails"
        ][0],
        lambda d: d["ConformancePackState"] == "CREATE_COMPLETE",
        timeout_s=180,
        interval_s=10,
    )
    assert detail["ConformancePackState"] == "CREATE_COMPLETE", (
        f"reason={detail.get('ConformancePackStatusReason')} detail={detail}"
    )

    # The rule's ACTUAL registered name is read off the pack's own compliance
    # listing rather than assumed to equal the template's ConfigRuleName: on AWS,
    # DescribeConfigRules(ConfigRuleNames=[<template name>]) never
    # found it (NoSuchConfigRuleException throughout the poll window) even though
    # DescribeConformancePackCompliance lists the rule under the pack immediately
    # once AWS Config's automatic initial evaluation has run.
    pack_rules = _poll_until(
        lambda: config.describe_conformance_pack_compliance(ConformancePackName=pack_name)[
            "ConformancePackRuleComplianceList"
        ],
        lambda rows: len(rows) > 0,
        timeout_s=240,
        interval_s=10,
    )
    assert len(pack_rules) == 1, f"expected exactly one rule in the pack, got {pack_rules}"
    actual_rule_name = pack_rules[0]["ConfigRuleName"]

    rule_state = _poll_until(
        lambda: _describe_rule_or_none(config, actual_rule_name),
        lambda r: r is not None and r["ConfigRuleState"] == "ACTIVE",
        timeout_s=120,
        interval_s=10,
    )
    assert rule_state is not None and rule_state["ConfigRuleState"] == "ACTIVE", rule_state

    # Force a fresh evaluation on top of AWS Config's automatic initial one
    # (the target bucket already existed before the rule did, so no new
    # ConfigurationItemChangeNotification would fire on its own).
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            config.start_config_rules_evaluation(ConfigRuleNames=[actual_rule_name])
            break
        except ClientError:  # e.g. ResourceInUseException while AWS auto-evaluates
            time.sleep(2)

    # INSUFFICIENT_DATA is also a truthy ComplianceType -- it means "not evaluated
    # yet", not a terminal result -- so the poll must wait for an actual verdict,
    # not merely a present field (a bare truthiness check would let INSUFFICIENT_DATA
    # through before the forced evaluation lands).
    rule_compliance = _poll_until(
        lambda: config.describe_conformance_pack_compliance(ConformancePackName=pack_name)[
            "ConformancePackRuleComplianceList"
        ],
        lambda rows: any(
            r.get("ComplianceType") in ("COMPLIANT", "NON_COMPLIANT")
            for r in rows
            if r["ConfigRuleName"] == actual_rule_name
        ),
        timeout_s=360,
        interval_s=15,
    )

    row = next(r for r in rule_compliance if r["ConfigRuleName"] == actual_rule_name)
    assert row["ComplianceType"] == "COMPLIANT", f"expected COMPLIANT, got {row['ComplianceType']}"

    summary = _poll_until(
        lambda: config.get_conformance_pack_compliance_summary(ConformancePackNames=[pack_name])[
            "ConformancePackComplianceSummaryList"
        ],
        lambda rows: len(rows) > 0,
        timeout_s=60,
        interval_s=5,
    )
    assert summary[0]["ConformancePackName"] == pack_name, (
        f"expected summary for {pack_name!r}, got {summary[0]['ConformancePackName']!r}"
    )
    assert summary[0]["ConformancePackComplianceStatus"] == "COMPLIANT", (
        f"expected COMPLIANT, got {summary[0]['ConformancePackComplianceStatus']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _retry_iam_propagation(fn, *, attempts=8, delay_s=5):
    """Retry a call that depends on a just-created IAM role/bucket-policy trust
    relationship having propagated, instead of a fixed pre-call sleep."""
    last_err = None
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(delay_s)
    raise last_err


def _describe_rule_or_none(config, rule_name):
    """A rule freshly created by a conformance pack can lag the pack's own
    CREATE_COMPLETE status: DescribeConfigRules(ConfigRuleNames=[...]) raises
    NoSuchConfigRuleException for a few seconds after the pack reports done.
    Treat that specific, transient not-found as "not yet" so the caller's
    poll keeps waiting instead of crashing on the first observation."""
    try:
        return config.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchConfigRuleException":
            return None
        raise


def _ensure_active_recorder(ctx):
    """Return (recorder_name, created) for an active, recording configuration
    recorder + delivery channel, provisioning one end-to-end (role, bucket,
    recorder, channel) and registering its teardown if none usable exists yet."""
    config = ctx.client("config")

    existing = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        name = existing[0]["name"]
        status = config.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[name]
        )["ConfigurationRecordersStatus"][0]
        if status.get("recording"):
            return name, False
        channels = config.describe_delivery_channels().get("DeliveryChannels", [])
        if channels:
            config.start_configuration_recorder(ConfigurationRecorderName=name)
            return name, False

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    name = ctx.unique_name("sim2real-cfghelper-rec-")
    bucket = ctx.unique_name("sim2real-cfghelper-bkt-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

    def _empty_and_delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)

    role_name = ctx.unique_name("sim2real-cfghelper-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
        )
    )
    account_id = sts.get_caller_identity()["Account"]
    bucket_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/Config/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    })
    s3.put_bucket_policy(Bucket=bucket, Policy=bucket_policy)

    # IAM is eventually consistent -- both calls below validate the new role (the
    # first via sts:AssumeRole, the second via the bucket policy that trusts it) and
    # reject it until propagation catches up. Retry the actual calls through that
    # window rather than trusting a fixed sleep.
    _retry_iam_propagation(
        lambda: config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": name,
                "roleARN": role_arn,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }
        )
    )
    ctx.on_cleanup(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=name))
    _retry_iam_propagation(
        lambda: config.put_delivery_channel(DeliveryChannel={"name": name, "s3BucketName": bucket})
    )
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=name))
    config.start_configuration_recorder(ConfigurationRecorderName=name)
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=name))
    return name, True


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
