"""remediation-configuration-echoes-automatic-retry-settings-and-refuses-out-of-range."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remediation-configuration-echoes-automatic-retry-settings-and-refuses-out-of-range"
GROUP = "visibility-timeout-ttl"
SERVICES = ["config"]

_CONFIG_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_RETRY_ATTEMPT_SECONDS = 65
_MAX_AUTOMATIC_ATTEMPTS = 2


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied, last observed value: {last!r}")


def _retry_while_error(fn, *, retry_codes, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in retry_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _ensure_recorder_recording(ctx) -> None:
    cfg = ctx.client("config")
    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        name = existing[0]["name"]
        status = cfg.describe_configuration_recorder_status(ConfigurationRecorderNames=[name])[
            "ConfigurationRecordersStatus"
        ][0]
        if not status.get("recording"):
            cfg.start_configuration_recorder(ConfigurationRecorderName=name)
            _poll_until(
                lambda: cfg.describe_configuration_recorder_status(ConfigurationRecorderNames=[name])[
                    "ConfigurationRecordersStatus"
                ][0]["recording"],
                lambda recording: recording is True,
                timeout_s=30,
            )
        return

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-cfgrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CONFIG_ROLE_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_CONFIG_ROLE_POLICY_ARN))

    bucket = ctx.unique_name("sim2real-cfgbucket-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSConfigBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSConfigBucketExistenceCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSConfigBucketDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/Config/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "AWS:SourceAccount": account_id,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

    recorder_name = ctx.unique_name("sim2real-recorder-")

    def _create_recorder():
        cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": recorder_name,
                "roleARN": role_arn,
                "recordingGroup": {"allSupported": False, "resourceTypes": ["AWS::S3::Bucket"]},
            }
        )

    _retry_while_error(_create_recorder, retry_codes=("InvalidRoleException",), timeout_s=90, interval_s=5)
    ctx.on_cleanup(lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name))

    def _create_delivery_channel():
        cfg.put_delivery_channel(DeliveryChannel={"name": recorder_name, "s3BucketName": bucket})

    # IAM role trust/assume-role propagation can lag a few seconds behind the
    # role's creation -- retry while Config can't yet assume the fresh role.
    _retry_while_error(
        _create_delivery_channel, retry_codes=("InsufficientDeliveryPolicyException",), timeout_s=90, interval_s=5
    )
    ctx.on_cleanup(lambda: cfg.delete_delivery_channel(DeliveryChannelName=recorder_name))

    cfg.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name))
    _poll_until(
        lambda: cfg.describe_configuration_recorder_status(ConfigurationRecorderNames=[recorder_name])[
            "ConfigurationRecordersStatus"
        ][0]["recording"],
        lambda recording: recording is True,
        timeout_s=30,
    )


def _create_no_permissions_automation_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ssmrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


_MAX_ATTEMPTS_CEILING = 25
_RETRY_SECONDS_FLOOR = 1
_RANGE_MESSAGE = (
    "1 validation error detected: Value '{value}' at "
    "'remediationConfigurations.1.member.{field}' failed to satisfy constraint: "
    "Member must have value {bound}"
)


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was accepted where a refusal was required: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """An automatic remediation configuration echoes its MaximumAutomaticAttempts and
    RetryAttemptSeconds window, and values outside 1-25 attempts or below 1 second are refused
    with the exact constraint message, leaving the stored configuration unchanged.

    Reference: https://docs.aws.amazon.com/config/latest/APIReference/API_RemediationConfiguration.html
    """
    _restore_config_recorder_on_teardown(ctx)
    _ensure_recorder_recording(ctx)
    cfg = ctx.client("config")
    raw_cfg = ctx.client("config", config=Config(parameter_validation=False))

    rule_name = ctx.unique_name("sim2real-versioning-rule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
        }
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))

    automation_role_arn = _create_no_permissions_automation_role(ctx)

    def _remediation(**overrides):
        body = {
            "ConfigRuleName": rule_name,
            "TargetType": "SSM_DOCUMENT",
            "TargetId": "AWS-ConfigureS3BucketVersioning",
            "Automatic": True,
            "MaximumAutomaticAttempts": _MAX_AUTOMATIC_ATTEMPTS,
            "RetryAttemptSeconds": _RETRY_ATTEMPT_SECONDS,
            "Parameters": {
                "BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}},
                "AutomationAssumeRole": {"StaticValue": {"Values": [automation_role_arn]}},
            },
        }
        body.update(overrides)
        return body

    put = cfg.put_remediation_configurations(RemediationConfigurations=[_remediation()])
    assert not put.get("FailedBatches"), f"PutRemediationConfigurations failed batches: {put['FailedBatches']!r}"
    ctx.on_cleanup(lambda: cfg.delete_remediation_configuration(ConfigRuleName=rule_name))

    def _stored():
        found = cfg.describe_remediation_configurations(ConfigRuleNames=[rule_name])["RemediationConfigurations"]
        assert len(found) == 1, f"DescribeRemediationConfigurations returned {found!r} for {rule_name!r}"
        r = found[0]
        return (r.get("Automatic"), r.get("MaximumAutomaticAttempts"), r.get("RetryAttemptSeconds"))

    want = (True, _MAX_AUTOMATIC_ATTEMPTS, _RETRY_ATTEMPT_SECONDS)
    assert _stored() == want, (
        f"stored (Automatic, MaximumAutomaticAttempts, RetryAttemptSeconds) is {_stored()!r}, expected {want!r}")

    refusals = [
        ("MaximumAutomaticAttempts", "maximumAutomaticAttempts", _MAX_ATTEMPTS_CEILING + 1,
         f"less than or equal to {_MAX_ATTEMPTS_CEILING}"),
        ("RetryAttemptSeconds", "retryAttemptSeconds", _RETRY_SECONDS_FLOOR - 1,
         f"greater than or equal to {_RETRY_SECONDS_FLOOR}"),
    ]
    for member, field, value, bound in refusals:
        code, message = _error(lambda m=member, v=value: raw_cfg.put_remediation_configurations(
            RemediationConfigurations=[_remediation(**{m: v})]))
        assert code == "ValidationException", f"{member}={value} refused with {code!r}"
        expected = _RANGE_MESSAGE.format(value=value, field=field, bound=bound)
        assert message == expected, f"{member}={value} message {message!r}, expected {expected!r}"
        assert _stored() == want, (
            f"after the refused {member}={value} the stored configuration is {_stored()!r}, expected {want!r}")


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
