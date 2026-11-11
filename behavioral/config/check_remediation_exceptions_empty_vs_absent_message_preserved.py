"""remediation-exceptions-empty-vs-absent-message-preserved."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "remediation-exceptions-empty-vs-absent-message-preserved"
GROUP = "representation"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A remediation exception put with a Message returns that exact text, and one put without a
    Message comes back with the field absent, not defaulted to an empty string.
    """
    # Exceptions are accepted only for NON_COMPLIANT resources, so an unversioned bucket is
    # evaluated under S3_BUCKET_VERSIONING_ENABLED first.
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")
    _ensure_config_recorder_running(ctx)

    rule_name = ctx.unique_name("sim2real-remexc-rule-")
    bucket_name = ctx.unique_name("sim2real-remexc-bucket-").replace("_", "-").lower()
    resource_type = "AWS::S3::Bucket"
    message_text = "explicit exception reason \u2014 approved by change-mgmt-1234"
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

    create_bucket_kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        create_bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_bucket_kwargs)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_delete_bucket)
    # Versioning is left disabled (the default) so this bucket is guaranteed
    # to be NON_COMPLIANT under S3_BUCKET_VERSIONING_ENABLED once evaluated.

    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Description": "sim2real behavioral remediation-exceptions rule",
            "Scope": {"ComplianceResourceTypes": [resource_type]},
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
        }
    )
    ctx.on_cleanup(lambda: _delete_rule_with_retry(cfg, rule_name))

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        rules = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
        if rules and rules[0]["ConfigRuleState"] == "ACTIVE":
            break
        time.sleep(1.0)
    else:
        raise AssertionError("config rule never became ACTIVE")

    # AWS Config discovers the bucket and runs its first evaluation
    # automatically on rule creation, but initial resource discovery for a
    # brand-new recorder can take a few minutes; poll generously and nudge
    # with an on-demand evaluation once the resource itself is discoverable.
    deadline = time.monotonic() + 480.0
    non_compliant = False
    last_kick = 0.0
    while time.monotonic() < deadline:
        results = cfg.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)[
            "EvaluationResults"
        ]
        non_compliant = any(
            r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
            == bucket_name
            and r["ComplianceType"] == "NON_COMPLIANT"
            for r in results
        )
        if non_compliant:
            break
        if time.monotonic() - last_kick > 60.0:
            try:
                cfg.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
            except Exception:  # noqa: BLE001 - best-effort nudge, e.g. throttled
                pass
            last_kick = time.monotonic()
        time.sleep(2)
    assert non_compliant, (
        "bucket was never evaluated NON_COMPLIANT under S3_BUCKET_VERSIONING_ENABLED"
    )

    automation_role_arn = _ensure_ssm_automation_role(ctx)

    deadline = time.monotonic() + 30.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            cfg.put_remediation_configurations(
                RemediationConfigurations=[
                    {
                        "ConfigRuleName": rule_name,
                        "TargetType": "SSM_DOCUMENT",
                        "TargetId": "AWS-StartEC2Instance",
                        "TargetVersion": "1",
                        "Parameters": {
                            "AutomationAssumeRole": {
                                "StaticValue": {"Values": [automation_role_arn]}
                            },
                            "InstanceId": {"StaticValue": {"Values": ["i-00000000000000000"]}},
                        },
                    }
                ]
            )
            last_error = None
            break
        except Exception as exc:  # noqa: BLE001 - retry until the rule and the
            # automation role are both visible/assumable (IAM propagation)
            last_error = exc
            time.sleep(2.0)
    if last_error is not None:
        m = getattr(last_error, "response", {}).get("Error", {}).get("Message", str(last_error))
        raise AssertionError(m)
    ctx.on_cleanup(lambda: cfg.delete_remediation_configuration(ConfigRuleName=rule_name))

    resource_key = {"ResourceType": resource_type, "ResourceId": bucket_name}

    def _cleanup_exceptions():
        try:
            cfg.delete_remediation_exceptions(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "NoSuchConfigRuleException",
                "NoSuchRemediationExceptionException",
            ):
                raise

    ctx.on_cleanup(_cleanup_exceptions)

    # 1) With an explicit Message.
    failed = cfg.put_remediation_exceptions(
        ConfigRuleName=rule_name,
        ResourceKeys=[resource_key],
        Message=message_text,
        ExpirationTime=expiration,
    )["FailedBatches"]
    assert failed == [], f"put with message failed unexpectedly: {failed}"

    with_msg_entry = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        exceptions = cfg.describe_remediation_exceptions(ConfigRuleName=rule_name)[
            "RemediationExceptions"
        ]
        matches = [e for e in exceptions if e["ResourceId"] == bucket_name]
        if matches:
            with_msg_entry = matches[0]
            break
        time.sleep(1.0)
    assert with_msg_entry is not None, "exception with message never appeared"
    assert with_msg_entry["Message"] == message_text, (
        f"message not byte-identical: {with_msg_entry.get('Message')!r} != {message_text!r}"
    )

    # 2) Clear it, then re-add the exception on the same resource key with no
    # Message at all -- the field must come back absent, not "" or reused.
    cfg.delete_remediation_exceptions(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        exceptions = cfg.describe_remediation_exceptions(ConfigRuleName=rule_name)[
            "RemediationExceptions"
        ]
        if not any(e["ResourceId"] == bucket_name for e in exceptions):
            break
        time.sleep(1.0)
    else:
        raise AssertionError("prior exception was never cleared before the no-message re-add")

    failed = cfg.put_remediation_exceptions(
        ConfigRuleName=rule_name,
        ResourceKeys=[resource_key],
    )["FailedBatches"]
    assert failed == [], f"put without message failed unexpectedly: {failed}"

    without_msg_entry = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        exceptions = cfg.describe_remediation_exceptions(ConfigRuleName=rule_name)[
            "RemediationExceptions"
        ]
        matches = [e for e in exceptions if e["ResourceId"] == bucket_name]
        if matches:
            without_msg_entry = matches[0]
            break
        time.sleep(1.0)
    assert without_msg_entry is not None, "exception without message never appeared"
    assert without_msg_entry.get("Message") is None, (
        f"absent message was not preserved as absent, got: {without_msg_entry.get('Message')!r}"
    )



def _delete_rule_with_retry(cfg, rule_name: str) -> None:
    # a rule with an evaluation or remediation still attached answers ResourceInUseException
    deadline = time.monotonic() + 30.0
    while True:
        try:
            cfg.delete_config_rule(ConfigRuleName=rule_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchConfigRuleException":
                return
            if code != "ResourceInUseException" or time.monotonic() > deadline:
                raise
        time.sleep(2.0)


def _ensure_ssm_automation_role(ctx) -> str:
    """Create a minimal ssm.amazonaws.com-assumable AutomationAssumeRole; a fabricated ARN is
    rejected with InsufficientPermissionsException."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ssm-automation-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["ssm.amazonaws.com", "config.amazonaws.com"]},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-ssm-automation-permissions",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:StartInstances",
                            "ec2:StopInstances",
                            "ec2:DescribeInstances",
                            "ec2:DescribeInstanceStatus",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-ssm-automation-permissions"))
    # IAM role trust/permissions propagation is absorbed by the caller's own
    # bounded retry on PutRemediationConfigurations (below), which is the
    # first call that actually depends on the role being assumable.
    return role_arn


def _ensure_config_recorder_running(ctx) -> str:
    """Ensure a started configuration recorder and delivery channel exist, creating the minimum
    needed with cleanup; returns the recorder name."""
    cfg = ctx.client("config")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    existing_recorders = cfg.describe_configuration_recorders().get(
        "ConfigurationRecorders", []
    )
    if existing_recorders:
        recorder_name = existing_recorders[0]["name"]
        role_arn = existing_recorders[0]["roleARN"]
    else:
        role_name = ctx.unique_name("sim2real-config-role-")
        bucket_name = ctx.unique_name("sim2real-config-bucket-").replace("_", "-").lower()
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
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust_policy,
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )["Role"]["Arn"]
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

        create_bucket_kwargs: dict[str, Any] = {"Bucket": bucket_name}
        if ctx.region != "us-east-1":
            create_bucket_kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": ctx.region
            }
        s3.create_bucket(**create_bucket_kwargs)
        s3.put_bucket_tagging(
            Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
        )

        def _delete_bucket():
            objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket_name)

        ctx.on_cleanup(_delete_bucket)

        # Config's delivery-permission check performs a real PutObject with the
        # bucket-owner-full-control canned ACL; buckets created since Apr 2023
        # default to ACLs-disabled ("BucketOwnerEnforced"), which makes that
        # check fail with InsufficientDeliveryPolicyException. Re-enable ACLs.
        s3.put_bucket_ownership_controls(
            Bucket=bucket_name,
            OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]},
        )

        account_id_for_policy = ctx.client("sts").get_caller_identity()["Account"]
        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AWSConfigBucketPermissionsCheck",
                            "Effect": "Allow",
                            "Principal": {"Service": "config.amazonaws.com"},
                            "Action": "s3:GetBucketAcl",
                            "Resource": f"arn:aws:s3:::{bucket_name}",
                            "Condition": {
                                "StringEquals": {"AWS:SourceAccount": account_id_for_policy}
                            },
                        },
                        {
                            "Sid": "AWSConfigBucketExistenceCheck",
                            "Effect": "Allow",
                            "Principal": {"Service": "config.amazonaws.com"},
                            "Action": "s3:ListBucket",
                            "Resource": f"arn:aws:s3:::{bucket_name}",
                            "Condition": {
                                "StringEquals": {"AWS:SourceAccount": account_id_for_policy}
                            },
                        },
                        {
                            "Sid": "AWSConfigBucketDelivery",
                            "Effect": "Allow",
                            "Principal": {"Service": "config.amazonaws.com"},
                            "Action": "s3:PutObject",
                            "Resource": f"arn:aws:s3:::{bucket_name}/*",
                            "Condition": {
                                "StringEquals": {
                                    "s3:x-amz-acl": "bucket-owner-full-control",
                                    "AWS:SourceAccount": account_id_for_policy,
                                }
                            },
                        },
                    ],
                }
            ),
        )

        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="sim2real-config-s3-delivery",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:PutObject", "s3:GetBucketAcl", "s3:ListBucket"],
                            "Resource": [
                                f"arn:aws:s3:::{bucket_name}",
                                f"arn:aws:s3:::{bucket_name}/*",
                            ],
                        }
                    ],
                }
            ),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-config-s3-delivery"))

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
            except Exception as exc:  # noqa: BLE001 - retry on any transient assume-role failure
                last_error = exc
                time.sleep(2.0)
        if last_error is not None:
            raise last_error
        ctx.on_cleanup(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )

        existing_channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
        if not existing_channels:
            channel_name = ctx.unique_name("sim2real-config-channel-")
            # The bucket policy we just wrote can take a few seconds to
            # propagate; Config's write-permission check for the delivery
            # channel is otherwise flaky right after put_bucket_policy.
            deadline = time.monotonic() + 30.0
            last_error = None
            while time.monotonic() < deadline:
                try:
                    cfg.put_delivery_channel(
                        DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}
                    )
                    last_error = None
                    break
                except Exception as exc:  # noqa: BLE001 - retry on transient policy propagation
                    last_error = exc
                    time.sleep(3.0)
            if last_error is not None:
                raise last_error
            ctx.on_cleanup(
                lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel_name)
            )

    status = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[recorder_name]
    )["ConfigurationRecordersStatus"][0]
    if not status.get("recording", False):
        cfg.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
        # stopped before the delivery channel's delete, which a running recorder refuses
        ctx.on_cleanup(
            lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        status = cfg.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[recorder_name]
        )["ConfigurationRecordersStatus"][0]
        if status.get("recording", False):
            return recorder_name
        time.sleep(1.0)
    raise AssertionError("configuration recorder never reached the 'recording' state")


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
