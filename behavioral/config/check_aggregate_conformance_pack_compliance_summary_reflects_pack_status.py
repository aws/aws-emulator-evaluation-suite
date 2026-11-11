"""aggregate-conformance-pack-compliance-summary-reflects-pack-status."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "aggregate-conformance-pack-compliance-summary-reflects-pack-status"
GROUP = "data-plane"
SERVICES = ["config"]


_OVERALL_BUDGET_S = 260.0  # stay under the harness's ~300s per-check wall-clock cap

_TEMPLATE = """Resources:
  IamPasswordPolicyCheck:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: {rule_name}
      Source:
        Owner: AWS
        SourceIdentifier: IAM_PASSWORD_POLICY
"""


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-aggregation-authorization", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A conformance pack's own compliance status is mirrored by the self-aggregator: the
    aggregate summary's compliant/non-compliant conformance-pack counts for this account add
    up to exactly one pack, on the side matching GetConformancePackComplianceSummary."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    start = time.monotonic()
    deadline = start + _OVERALL_BUDGET_S

    _ensure_recording(ctx)
    aggregator_name = ctx.unique_name("sim2real-agg-")
    account_id, region = _setup_self_aggregator(ctx, aggregator_name)

    pack_name = ctx.unique_name("sim2real-conf-pack-")
    rule_name = ctx.unique_name("sim2real-iampw-")
    config.put_conformance_pack(
        ConformancePackName=pack_name, TemplateBody=_TEMPLATE.format(rule_name=rule_name)
    )
    ctx.on_cleanup(lambda: config.delete_conformance_pack(ConformancePackName=pack_name))

    pack_budget = max(30.0, (deadline - time.monotonic()) * 0.4)
    pack_status = _poll_until(
        lambda: config.describe_conformance_pack_status(
            ConformancePackNames=[pack_name]
        )["ConformancePackStatusDetails"][0],
        lambda s: s["ConformancePackState"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=pack_budget,
        interval_s=5,
    )
    assert pack_status is not None and pack_status["ConformancePackState"] == "CREATE_COMPLETE", (
        f"conformance pack did not reach CREATE_COMPLETE: {pack_status}, "
        f"reason={pack_status.get('ConformancePackStatusReason') if pack_status else None}"
    )

    def _source_summary_probe():
        summaries = config.get_conformance_pack_compliance_summary(
            ConformancePackNames=[pack_name]
        )["ConformancePackComplianceSummaryList"]
        return summaries[0] if summaries else None

    source_budget = max(20.0, (deadline - time.monotonic()) * 0.5)
    source_summary = _poll_until(
        _source_summary_probe,
        lambda s: s is not None and s["ConformancePackComplianceStatus"] in ("COMPLIANT", "NON_COMPLIANT"),
        timeout_s=source_budget,
        interval_s=8,
    )
    if source_summary is None:
        raise AssertionError(
            f"the conformance pack's own rule never reached a final compliance status "
            f"within {source_budget:.0f}s; AWS Config's first evaluation of a brand-new "
            "conformance pack rule can take longer than this check's time budget allows.",
        )
    expected_status = source_summary["ConformancePackComplianceStatus"]

    def _aggregate_probe():
        summaries = config.get_aggregate_conformance_pack_compliance_summary(
            ConfigurationAggregatorName=aggregator_name,
            Filters={"AccountId": account_id, "AwsRegion": region},
        )["AggregateConformancePackComplianceSummaries"]
        if not summaries:
            return None
        summary = summaries[0]["ComplianceSummary"]
        if summary["CompliantConformancePackCount"] + summary["NonCompliantConformancePackCount"] < 1:
            return None
        return summary

    aggregate_budget = max(15.0, deadline - time.monotonic() - 5)
    summary = _poll_until(
        _aggregate_probe,
        lambda s: s is not None,
        timeout_s=aggregate_budget,
        interval_s=8,
    )
    if summary is None:
        raise AssertionError(
            "the source-account pack reached a final compliance status, but the "
            f"aggregator never reported a non-zero summary within {aggregate_budget:.0f}s; "
            "aggregation propagation lag exceeded this check's remaining time budget."
        )

    compliant = summary["CompliantConformancePackCount"]
    noncompliant = summary["NonCompliantConformancePackCount"]
    assert compliant + noncompliant == 1, (
        f"expected exactly one conformance pack's compliance reflected for this account, "
        f"got compliant={compliant}, noncompliant={noncompliant}"
    )
    if expected_status == "COMPLIANT":
        assert compliant == 1 and noncompliant == 0, (
            f"source pack reported COMPLIANT but the aggregate summary shows "
            f"compliant={compliant}, noncompliant={noncompliant}"
        )
    else:
        assert noncompliant == 1 and compliant == 0, (
            f"source pack reported NON_COMPLIANT but the aggregate summary shows "
            f"compliant={compliant}, noncompliant={noncompliant}"
        )


# ===== self-contained helpers =====
def _ensure_recording(ctx):
    """AWS::Config::ConfigRule resources (used by conformance packs) require a
    running configuration recorder in the account/region. Reuses any pre-existing
    recorder/delivery-channel untouched; only tears down what it creates itself."""
    config = ctx.client("config")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if recorders:
        recorder_name = recorders[0]["name"]
    else:
        role_name = ctx.unique_name("sim2real-cfgrole-")
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
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
            ),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        role_arn = role["Role"]["Arn"]
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
        )
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        ctx.on_cleanup(
            lambda: iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
            )
        )

        recorder_name = "default"

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
        return recorder_name

    channels = config.describe_delivery_channels().get("DeliveryChannels", [])
    if channels:
        channel_name = channels[0]["name"]
    else:
        account_id = sts.get_caller_identity()["Account"]
        bucket_name = ctx.unique_name("sim2real-cfg-").lower()
        # S3's global endpoint rejects an explicit LocationConstraint for us-east-1 itself;
        # every other region requires one.
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

        channel_name = "default"
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
    return recorder_name


def _empty_and_delete_bucket(s3, bucket_name):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _setup_self_aggregator(ctx, aggregator_name):

    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    config.put_aggregation_authorization(
        AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
    )
    ctx.on_cleanup(
        lambda: config.delete_aggregation_authorization(
            AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
        )
    )

    config.put_configuration_aggregator(
        ConfigurationAggregatorName=aggregator_name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AllAwsRegions": False, "AwsRegions": [region]}
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: config.delete_configuration_aggregator(
            ConfigurationAggregatorName=aggregator_name
        )
    )
    return account_id, region


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last if last is not None and predicate(last) else None


def _retry_on(fn, error_codes, *, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            if code not in error_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
