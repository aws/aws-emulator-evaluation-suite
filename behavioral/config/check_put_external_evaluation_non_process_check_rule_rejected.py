"""put-external-evaluation-non-process-check-rule-rejected."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-external-evaluation-non-process-check-rule-rejected"
GROUP = "data-plane"
SERVICES = ["config"]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder",
)
def run(ctx) -> None:
    """PutExternalEvaluation on an existing non-process-check rule is rejected with
    InvalidParameterValueException and records nothing; PutConfigRule refuses
    AWS_CONFIG_PROCESS_CHECK as a source identifier and leaves no rule behind.
    """
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _ensure_recorder_and_channel(ctx)

    # A real, non-process-check managed rule: no resource Scope needed, so it
    # activates without waiting on any evaluation.
    managed_rule_name = ctx.unique_name("sim2real-managed-rule-")
    config.put_config_rule(
        ConfigRule={
            "ConfigRuleName": managed_rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "IAM_PASSWORD_POLICY"},
        }
    )
    ctx.on_cleanup(lambda: config.delete_config_rule(ConfigRuleName=managed_rule_name))

    ordering_timestamp = datetime.now(timezone.utc)
    code, code_message = _error(
        lambda: config.put_external_evaluation(
            ConfigRuleName=managed_rule_name,
            ExternalEvaluation={
                "ComplianceResourceType": "AWS::::Account",
                "ComplianceResourceId": account_id,
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "should-be-rejected",
                "OrderingTimestamp": ordering_timestamp,
            },
        )
    )
    assert code == "InvalidParameterValueException", (
        f"PutExternalEvaluation against an existing non-process-check rule must be "
        f"rejected with InvalidParameterValueException (measured on real AWS -- the "
        f"rule exists, so the refusal is about its type, not NoSuchConfigRuleException, "
        f"which is reserved for a rule name that does not exist at all); got {code!r}"
    )
    assert code_message == (
        "This API can only be applied to rules with sourceIdentifier as AWS_CONFIG_PROCESS_CHECK."
    ), code_message

    # Effect absent: no external-evaluation-sourced result was recorded for the
    # managed rule (it only ever gets Lambda/managed-rule-sourced evaluations).
    details = config.get_compliance_details_by_resource(
        ResourceType="AWS::::Account", ResourceId=account_id
    )["EvaluationResults"]
    fabricated = [
        r
        for r in details
        if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ConfigRuleName"]
        == managed_rule_name
        and r.get("Annotation") == "should-be-rejected"
    ]
    assert fabricated == [], (
        f"a rejected PutExternalEvaluation must record no evaluation result for "
        f"{managed_rule_name!r}; found {fabricated!r}"
    )

    # PutConfigRule does not accept AWS_CONFIG_PROCESS_CHECK, so no process-check rule can serve
    # as an accept-path control; the refusal itself is asserted instead.
    process_check_rule_name = ctx.unique_name("sim2real-process-check-")
    create_code, create_code_message = _error(
        lambda: config.put_config_rule(
            ConfigRule={
                "ConfigRuleName": process_check_rule_name,
                "Source": {"Owner": "AWS", "SourceIdentifier": "AWS_CONFIG_PROCESS_CHECK"},
            }
        )
    )
    assert create_code == "InvalidParameterValueException", (
        f"AWS_CONFIG_PROCESS_CHECK is withdrawn from PutConfigRule with "
        f"InvalidParameterValueException naming the sourceIdentifier as invalid; got {create_code!r}"
    )
    assert create_code_message == (
        "The sourceIdentifier AWS_CONFIG_PROCESS_CHECK is invalid. Please refer to the "
        "documentation for a list of valid sourceIdentifiers that can be used when AWS is the Owner."
    ), create_code_message

    # Effect absent: no rule was fabricated under this name.
    describe_code, describe_code_message = _error(
        lambda: config.describe_config_rules(ConfigRuleNames=[process_check_rule_name])
    )
    assert describe_code == "NoSuchConfigRuleException", (
        f"a refused PutConfigRule must leave no rule behind; DescribeConfigRules for "
        f"{process_check_rule_name!r} should raise NoSuchConfigRuleException, got {describe_code!r}"
    )
    assert describe_code_message == (
        "One or more ConfigRules provided in the request are invalid. Please check the configRule names."
    ), describe_code_message



def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket_name)


def _ensure_recorder_and_channel(ctx):
    config = ctx.client("config")
    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if recorders:
        name = recorders[0]["name"]
        status = config.describe_configuration_recorder_status(ConfigurationRecorderNames=[name])[
            "ConfigurationRecordersStatus"
        ][0]
        if not status.get("recording"):
            config.start_configuration_recorder(ConfigurationRecorderName=name)
        return name

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-cfg-recorder-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
        )
    )

    bucket_name = ctx.unique_name("sim2real-cfg-bucket-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
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
                "Sid": "AWSConfigBucketExistenceCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:ListBucket",
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

    recorder_name = ctx.unique_name("sim2real-cfg-recorder-")
    deadline = time.monotonic() + 90
    while True:
        try:
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    # includeGlobalResourceTypes is valid only alongside allSupported=True
                    # (InvalidRecordingGroupException otherwise), so AWS::IAM::Role is named.
                    "recordingGroup": {"allSupported": False, "resourceTypes": ["AWS::IAM::Role"]},
                }
            )
            break
        except ClientError as e:
            if (
                e.response["Error"]["Code"] == "InvalidRoleException"
                and time.monotonic() < deadline
            ):
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(
        lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
    )

    # A new recorder role can still fail with InsufficientDeliveryPolicyException "unable to
    # assume role" for several seconds after creation, so that error is retried to a deadline.
    channel_deadline = time.monotonic() + 60
    while True:
        try:
            config.put_delivery_channel(
                DeliveryChannel={"name": recorder_name, "s3BucketName": bucket_name}
            )
            break
        except ClientError as e:
            if (
                e.response["Error"]["Code"] == "InsufficientDeliveryPolicyException"
                and time.monotonic() < channel_deadline
            ):
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=recorder_name))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(
        lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name)
    )
    return recorder_name


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
