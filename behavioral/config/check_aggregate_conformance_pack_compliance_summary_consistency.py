"""aggregate-conformance-pack-compliance-summary-consistency."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aggregate-conformance-pack-compliance-summary-consistency"
GROUP = "data-plane"
SERVICES = ["config"]

# Stay under the ~300s per-check time limit; pack deployment, external-evaluation propagation
# and aggregator sync are each slow on AWS.
_OVERALL_BUDGET_S = 260.0


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-aggregation-authorization", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A conformance pack's process-check rule marked NON_COMPLIANT via PutExternalEvaluation is
    reported by DescribeConformancePackCompliance and then rolled up into a self-aggregator's
    GetAggregateConformancePackComplianceSummary."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    deadline = time.monotonic() + _OVERALL_BUDGET_S

    _ensure_recording(ctx)

    # An aggregator's own account must authorize itself as a source, even for
    # self-account aggregation. The aggregator is set up before the pack exists,
    # which converges faster.
    config.put_aggregation_authorization(AuthorizedAccountId=account_id, AuthorizedAwsRegion=ctx.region)
    ctx.on_cleanup(
        lambda: config.delete_aggregation_authorization(
            AuthorizedAccountId=account_id, AuthorizedAwsRegion=ctx.region
        )
    )

    agg_name = ctx.unique_name("sim2real-cpack-agg-")
    config.put_configuration_aggregator(
        ConfigurationAggregatorName=agg_name,
        AccountAggregationSources=[{"AccountIds": [account_id], "AllAwsRegions": False, "AwsRegions": [ctx.region]}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: config.delete_configuration_aggregator(ConfigurationAggregatorName=agg_name))

    pack_name = ctx.unique_name("sim2real-cpack-")
    rule_prefix = ctx.unique_name("sim2real-cpack-rule-")
    template = f"""Resources:
  Sim2RealProcessCheck:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: {rule_prefix}
      Description: sim2real behavioral check process check rule
      Source:
        Owner: AWS
        SourceIdentifier: AWS_CONFIG_PROCESS_CHECK
"""
    config.put_conformance_pack(
        ConformancePackName=pack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_conformance_pack(config, pack_name))

    pack_budget = max(30.0, (deadline - time.monotonic()) * 0.45)
    pack_status = _poll_until(
        lambda: config.describe_conformance_pack_status(ConformancePackNames=[pack_name])["ConformancePackStatusDetails"][0],
        lambda s: s["ConformancePackState"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=pack_budget,
        interval_s=10,
    )
    assert pack_status["ConformancePackState"] == "CREATE_COMPLETE", (
        f"conformance pack did not reach CREATE_COMPLETE: state={pack_status['ConformancePackState']!r}, "
        f"reason={pack_status.get('ConformancePackStatusReason')!r}"
    )

    # A conformance pack may append a random suffix to the ConfigRuleName given
    # in its template, so resolve the actual created rule by prefix rather than
    # trusting the literal name back.
    rule_name = _find_rule_by_prefix(config, rule_prefix)
    assert rule_name is not None, (
        f"no config rule found with name prefix {rule_prefix!r} after conformance "
        f"pack {pack_name!r} reached CREATE_COMPLETE"
    )

    config.put_external_evaluation(
        ConfigRuleName=rule_name,
        ExternalEvaluation={
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": account_id,
            "ComplianceType": "NON_COMPLIANT",
            "Annotation": "sim2real-behavioral-check",
            "OrderingTimestamp": datetime.now(timezone.utc),
        },
    )

    compliance_budget = max(20.0, (deadline - time.monotonic()) * 0.4)
    _poll_until(
        lambda: config.describe_conformance_pack_compliance(ConformancePackName=pack_name)["ConformancePackRuleComplianceList"],
        lambda rules: any(r["ConfigRuleName"] == rule_name and r["ComplianceType"] == "NON_COMPLIANT" for r in rules),
        timeout_s=compliance_budget,
        interval_s=5,
    )

    def _summary_reflects_noncompliant_pack():
        resp = config.get_aggregate_conformance_pack_compliance_summary(
            ConfigurationAggregatorName=agg_name,
            Filters={"AccountId": account_id, "AwsRegion": ctx.region},
        )
        summaries = resp["AggregateConformancePackComplianceSummaries"]
        total = sum(s["ComplianceSummary"]["NonCompliantConformancePackCount"] for s in summaries)
        return {"noncompliant": total, "raw": summaries}

    summary_budget = max(15.0, deadline - time.monotonic() - 5)
    _poll_until(
        _summary_reflects_noncompliant_pack,
        lambda r: r["noncompliant"] >= 1,
        timeout_s=summary_budget,
        interval_s=10,
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _ensure_recording(ctx) -> None:
    """Ensure a RECORDING recorder with a delivery channel: pack compliance is never computed
    otherwise, even for a process-check rule. Only tears down what it creates or starts."""
    config = ctx.client("config")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if recorders:
        recorder_name = recorders[0]["name"]
    else:
        role_name = ctx.unique_name("sim2real-cfgrole-")
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
        role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
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

        recorder_name = ctx.unique_name("sim2real-cfgrec-")

        def _create_recorder():
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )

        _retry_on(_create_recorder, ("InvalidRoleException",), timeout_s=60, interval_s=5)
        ctx.on_cleanup(
            lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )

    recorder_status = config.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[recorder_name]
    )["ConfigurationRecordersStatus"][0]
    if recorder_status.get("recording"):
        return

    channels = config.describe_delivery_channels().get("DeliveryChannels", [])
    if channels:
        channel_name = channels[0]["name"]
    else:
        account_id = sts.get_caller_identity()["Account"]
        bucket_name = ctx.unique_name("sim2real-cfg-").lower()
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": ctx.region},
            )
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

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

        channel_name = ctx.unique_name("sim2real-cfgchan-")
        _retry_on(
            lambda: config.put_delivery_channel(
                DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}
            ),
            ("InsufficientDeliveryPolicyException", "NoSuchBucketException"),
            timeout_s=60,
            interval_s=5,
        )
        ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name))


def _empty_and_delete_bucket(s3, bucket_name):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _retry_on(fn, error_codes, *, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in error_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _find_rule_by_prefix(config, name_prefix: str) -> str | None:
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = config.describe_config_rules(**kwargs)
        for rule in resp.get("ConfigRules", []):
            if rule["ConfigRuleName"].startswith(name_prefix):
                return rule["ConfigRuleName"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


def _delete_conformance_pack(config, pack_name):
    deadline = time.monotonic() + 120
    while True:
        try:
            config.delete_conformance_pack(ConformancePackName=pack_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchConformancePackException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


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
