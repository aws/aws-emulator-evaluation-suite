"""conformance-pack-compliance-details-and-summary-consistent."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "conformance-pack-compliance-details-and-summary-consistent"
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


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """After a conformance pack reaches CREATE_COMPLETE, GetConformancePackComplianceSummary reports
    NON_COMPLIANT for it if any rule result from GetConformancePackComplianceDetails is NON_COMPLIANT,
    else COMPLIANT."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    start = time.monotonic()
    deadline = start + _OVERALL_BUDGET_S
    _ensure_recording(ctx)

    pack_name = ctx.unique_name("sim2real-conf-pack-")
    rule_name = ctx.unique_name("sim2real-iampw-")
    template = _TEMPLATE.format(rule_name=rule_name)

    config.put_conformance_pack(ConformancePackName=pack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: config.delete_conformance_pack(ConformancePackName=pack_name))

    pack_budget = max(30.0, (deadline - time.monotonic()) * 0.4)
    status = _poll_until(
        lambda: config.describe_conformance_pack_status(
            ConformancePackNames=[pack_name]
        )["ConformancePackStatusDetails"][0],
        lambda s: s["ConformancePackState"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=pack_budget,
        interval_s=5,
    )
    assert status is not None and status["ConformancePackState"] == "CREATE_COMPLETE", (
        f"conformance pack did not reach CREATE_COMPLETE: {status}, "
        f"reason={status.get('ConformancePackStatusReason') if status else None}"
    )

    details_budget = max(20.0, (deadline - time.monotonic()) * 0.6)
    details = _poll_until(
        lambda: config.get_conformance_pack_compliance_details(
            ConformancePackName=pack_name
        )["ConformancePackRuleEvaluationResults"],
        lambda results: len(results) > 0,
        timeout_s=details_budget,
        interval_s=8,
    )
    if not details:
        raise AssertionError(
            f"the conformance pack's rule never produced an evaluation result within "
            f"{details_budget:.0f}s; AWS Config's first evaluation of a brand-new "
            "conformance pack rule can take longer than this check's time budget allows."
        )


    compliance_types = {r["ComplianceType"] for r in details}
    expected_overall = "NON_COMPLIANT" if "NON_COMPLIANT" in compliance_types else "COMPLIANT"

    summary_budget = max(15.0, deadline - time.monotonic() - 5)
    summary = _poll_until(
        lambda: config.get_conformance_pack_compliance_summary(
            ConformancePackNames=[pack_name]
        )["ConformancePackComplianceSummaryList"][0],
        lambda s: s["ConformancePackComplianceStatus"] == expected_overall,
        timeout_s=summary_budget,
        interval_s=8,
    )
    assert summary is not None, (
        f"summary never matched detail-derived status {expected_overall}"
    )
    assert summary["ConformancePackName"] == pack_name, (
        f"expected summary for pack {pack_name!r}, got {summary['ConformancePackName']!r}"
    )
    assert summary["ConformancePackComplianceStatus"] == expected_overall, (
        f"expected summary status {expected_overall} (derived from detail rows "
        f"{sorted(compliance_types)}), got {summary['ConformancePackComplianceStatus']!r}"
    )


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
        # registered first so it runs after the policy detaches and deletes below
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
        if ctx.region == "us-east-1":
            # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself;
            # this branches on ctx.region for API compatibility, it does not pin the check
            # to a specific region.
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": ctx.region},
            )
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
        s3.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last if last is not None and predicate(last) else None


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
