"""remediation-execution-retry-backoff-and-timeout."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "remediation-execution-retry-backoff-and-timeout"
GROUP = "visibility-timeout-ttl"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutRemediationConfigurations persists RetryAttemptSeconds/MaximumAutomaticAttempts, and
    StartRemediationExecution on a NON_COMPLIANT bucket drives the execution through
    QUEUED -> IN_PROGRESS to a terminal state rather than staying IN_PROGRESS."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    iam = ctx.client("iam")
    sns = ctx.client("sns")
    s3 = ctx.client("s3")

    _ensure_customer_managed_recorder(ctx, config, iam, s3)

    rule_name = ctx.unique_name("sim2real-behav-remrule-")
    config.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: config.delete_config_rule(ConfigRuleName=rule_name))

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-remtopic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    role_arn = _create_ssm_automation_role(ctx, iam, topic_arn)

    put_resp = config.put_remediation_configurations(
        RemediationConfigurations=[
            {
                "ConfigRuleName": rule_name,
                "TargetType": "SSM_DOCUMENT",
                "TargetId": "AWS-PublishSNSNotification",
                "Automatic": False,
                "MaximumAutomaticAttempts": 2,
                "RetryAttemptSeconds": 65,
                "Parameters": {
                    "TopicArn": {"StaticValue": {"Values": [topic_arn]}},
                    "Message": {"StaticValue": {"Values": ["sim2real-remediation-test"]}},
                    "AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}},
                },
            }
        ]
    )
    assert not put_resp.get("FailedBatches"), f"put_remediation_configurations reported failed batches: {put_resp.get('FailedBatches')}"
    ctx.on_cleanup(lambda: config.delete_remediation_configuration(ConfigRuleName=rule_name))

    persisted = config.describe_remediation_configurations(ConfigRuleNames=[rule_name])
    remediation = persisted["RemediationConfigurations"][0]
    assert remediation["RetryAttemptSeconds"] == 65, f"expected RetryAttemptSeconds=65, got {remediation['RetryAttemptSeconds']}"
    assert remediation["MaximumAutomaticAttempts"] == 2, f"expected MaximumAutomaticAttempts=2, got {remediation['MaximumAutomaticAttempts']}"

    # StartRemediationExecution refuses a resource key with no NON_COMPLIANT evaluation
    # result for the rule (FailedItems: "There are no non-compliant EvaluationResult for the
    # resource(s) ..."), so the target must be a real bucket evaluated NON_COMPLIANT.
    bucket = ctx.unique_name("sim2real-behav-target-")
    if ctx.region == "us-east-1":
        # S3 rejects an explicit LocationConstraint of us-east-1 -- the literal here
        # is CreateBucket's own special case for that region, not a pinned target.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    # Bucket intentionally left without versioning enabled -> NON_COMPLIANT.
    resource_key = {"resourceType": "AWS::S3::Bucket", "resourceId": bucket}

    eval_resp = config.start_config_rules_evaluation(ConfigRuleNames=[rule_name])

    def _all_results():
        return config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)["EvaluationResults"]

    def _is_noncompliant() -> bool:
        return any(
            r["EvaluationResultIdentifier"]["EvaluationResultQualifier"].get("ResourceId") == bucket
            and r["ComplianceType"] == "NON_COMPLIANT"
            for r in _all_results()
        )

    noncompliant_deadline = time.monotonic() + 200.0
    last_results = None
    while time.monotonic() < noncompliant_deadline and not _is_noncompliant():
        last_results = _all_results()
        time.sleep(2)
    assert _is_noncompliant(), (
        f"bucket {bucket} was never evaluated NON_COMPLIANT by {rule_name} within 200s; "
        f"start_config_rules_evaluation response: {eval_resp}; last seen evaluation results: {last_results}"
    )

    def _run_execution_once():
        start_resp = config.start_remediation_execution(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
        assert not start_resp.get("FailedItems"), (
            f"start_remediation_execution rejected the resource key: "
            f"FailureMessage={start_resp.get('FailureMessage')!r} FailedItems={start_resp.get('FailedItems')}"
        )
        state = None
        last_response = None
        poll_deadline = time.monotonic() + 60.0
        while time.monotonic() < poll_deadline:
            status = config.describe_remediation_execution_status(
                ConfigRuleName=rule_name, ResourceKeys=[resource_key]
            )
            statuses = status["RemediationExecutionStatuses"]
            last_response = status
            if statuses and statuses[0]["State"] not in ("QUEUED", "IN_PROGRESS"):
                state = statuses[0]
                break
            time.sleep(3)
        return state, last_response

    # A manual (Automatic=False) invocation does NOT get Config's own
    # MaximumAutomaticAttempts/RetryAttemptSeconds retries. One that hits the
    # AutomationAssumeRole before IAM has propagated it terminates FAILED in under a second
    # ("AccessDeniedException while calling STS"), so that signature gets a bounded retry.
    retry_deadline = time.monotonic() + 120.0
    final_state = None
    last_status_response = None
    while True:
        final_state, last_status_response = _run_execution_once()
        if final_state is not None and final_state["State"] == "SUCCEEDED":
            break
        is_transient_role_propagation = final_state is not None and any(
            "AccessDeniedException while calling STS" in (step.get("ErrorMessage") or "")
            for step in final_state.get("StepDetails", [])
        )
        if not is_transient_role_propagation or time.monotonic() >= retry_deadline:
            break
        time.sleep(5)

    assert final_state is not None, (
        f"remediation execution never left QUEUED/IN_PROGRESS; "
        f"last describe_remediation_execution_status response: {last_status_response}"
    )
    assert final_state["State"] == "SUCCEEDED", f"expected terminal state SUCCEEDED, got {final_state['State']}: {final_state}"
    assert final_state["StepDetails"], f"expected non-empty StepDetails on a terminal execution, got {final_state}"
    for step in final_state["StepDetails"]:
        if "StartTime" in step and "StopTime" in step:
            assert step["StartTime"] <= step["StopTime"], (
                f"step {step.get('Name')} has StopTime before StartTime: {step['StartTime']} > {step['StopTime']}"
            )



def _ensure_customer_managed_recorder(ctx, config, iam, s3) -> None:
    existing = config.describe_configuration_recorders()["ConfigurationRecorders"]
    for rec in existing:
        if not rec.get("servicePrincipal"):
            return  # a customer-managed recorder already exists; reuse it, don't own its lifecycle

    role_name = ctx.unique_name("sim2real-behav-config-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
        )
    )

    # IAM role propagation is eventually consistent: Config rejects a freshly
    # created role with InvalidRoleException until it can assume it. Bound the
    # wait instead of sleeping a fixed amount.
    deadline = time.monotonic() + 60.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": "default",
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )
            break
        except config.exceptions.InvalidRoleException as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise AssertionError(
            f"put_configuration_recorder never accepted the freshly created role {role_arn} "
            f"within 60s; last error: {last_exc}"
        )
    ctx.on_cleanup(lambda: config.delete_configuration_recorder(ConfigurationRecorderName="default"))

    # StartConfigurationRecorder requires a delivery channel to exist
    # (NoAvailableDeliveryChannelException otherwise); a recorder alone never records.
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-cfgbucket-")
    if ctx.region == "us-east-1":
        # S3 rejects an explicit LocationConstraint of us-east-1 -- the literal here
        # is CreateBucket's own special case for that region, not a pinned target.
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

    deadline = time.monotonic() + 60.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            config.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": bucket})
            break
        except config.exceptions.InsufficientDeliveryPolicyException as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise AssertionError(
            f"put_delivery_channel never accepted the freshly created bucket policy on {bucket} "
            f"within 60s; last error: {last_exc}"
        )
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName="default"))

    config.start_configuration_recorder(ConfigurationRecorderName="default")
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName="default"))
    recording_deadline = time.monotonic() + 30.0
    while time.monotonic() < recording_deadline:
        status = config.describe_configuration_recorder_status(ConfigurationRecorderNames=["default"])[
            "ConfigurationRecordersStatus"
        ][0]
        if status.get("recording"):
            break
        time.sleep(2)
    else:
        raise AssertionError("configuration recorder 'default' never reached recording=True within 30s")


def _create_ssm_automation_role(ctx, iam, topic_arn: str) -> str:
    role_name = ctx.unique_name("sim2real-behav-ssm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-behav-ssm-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # No fixed sleep for role/policy propagation here: the caller's bounded poll
    # on describe_remediation_execution_status, plus Config's own
    # MaximumAutomaticAttempts/RetryAttemptSeconds retry of the automation
    # itself, already absorb that eventual-consistency window.
    return role_arn


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
