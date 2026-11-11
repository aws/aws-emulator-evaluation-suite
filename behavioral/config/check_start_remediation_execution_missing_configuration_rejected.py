"""start-remediation-execution-missing-configuration-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "start-remediation-execution-missing-configuration-rejected"
GROUP = "e2e"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """StartRemediationExecution fails with NoSuchRemediationConfigurationException for a rule without a
    remediation configuration and leaves no execution behind, while a sibling rule with one accepts
    the call and drives a real execution to SUCCEEDED."""
    _restore_config_recorder_on_teardown(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    config = ctx.client("config")

    _ensure_configuration_recorder(ctx)

    rule_without_remediation = ctx.unique_name("sim2real-no-remediation-")
    rule_with_remediation = ctx.unique_name("sim2real-with-remediation-")
    for name in (rule_without_remediation, rule_with_remediation):
        config.put_config_rule(
            ConfigRule={
                "ConfigRuleName": name,
                "Source": {"Owner": "AWS", "SourceIdentifier": "CLOUD_TRAIL_ENABLED"},
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: _safe(lambda: config.delete_config_rule(ConfigRuleName=n), "NoSuchConfigRuleException", busy=("ResourceInUseException",)))
        _poll_rule_active(config, name)

    automation_role_arn = _create_automation_role(ctx)
    doc_name = _create_noop_document(ctx)

    config.put_remediation_configurations(
        RemediationConfigurations=[
            {
                "ConfigRuleName": rule_with_remediation,
                "TargetType": "SSM_DOCUMENT",
                "TargetId": doc_name,
                "Parameters": {"AutomationAssumeRole": {"StaticValue": {"Values": [automation_role_arn]}}},
                "Automatic": False,
            }
        ]
    )
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_remediation_configuration(ConfigRuleName=rule_with_remediation), "NoSuchRemediationConfigurationException", busy=("RemediationInProgressException",)))

    resource_key = {"resourceType": "AWS::::Account", "resourceId": account_id}

    # Negative: no remediation configuration exists for this rule.
    start_code, start_message = _error(
        lambda: config.start_remediation_execution(ConfigRuleName=rule_without_remediation, ResourceKeys=[resource_key])
    )
    assert start_code == "NoSuchRemediationConfigurationException", (
        f"expected NoSuchRemediationConfigurationException for a rule with no remediation "
        f"configuration, got {start_code!r}"
    )
    expected_start = (
        f"There is no applicable RemediationConfiguration setup for AWS Config rule {rule_without_remediation}"
    )
    assert start_message == expected_start, f"expected {expected_start!r}, got {start_message!r}"

    # Effect absent: there is nothing to describe either -- no execution was queued,
    # and there never was a remediation configuration to hold one.
    describe_code, describe_message = _error(
        lambda: config.describe_remediation_execution_status(
            ConfigRuleName=rule_without_remediation, ResourceKeys=[resource_key]
        )
    )
    assert describe_code == "NoSuchRemediationConfigurationException", (
        f"expected NoSuchRemediationConfigurationException describing a rule with no remediation "
        f"configuration, got {describe_code!r}"
    )
    expected_describe = (
        f"There is no RemediationConfiguration setup for AWS Config rule {rule_without_remediation}."
    )
    assert describe_message == expected_describe, (
        f"expected {expected_describe!r}, got {describe_message!r}"
    )

    # Positive control: the sibling rule with a real remediation configuration
    # accepts the call and produces an actual execution record. Retry on
    # FailedItems too -- the automation IAM role was just created and may not
    # have propagated to STS assume-role checks yet, and a rule on a recorder this
    # check just started has no NON_COMPLIANT evaluation for the account for minutes.
    start_resp = _retry_until_no_failed_items(
        lambda: config.start_remediation_execution(ConfigRuleName=rule_with_remediation, ResourceKeys=[resource_key]),
        attempts=36,
        delay=10.0,
    )
    assert start_resp.get("FailedItems", []) == [], start_resp
    # The automation document is a no-op sleep with a role scoped to nothing but assuming
    # it, so the execution must reach SUCCEEDED, not merely be queued.
    status = _poll_for_terminal_status_entry(config, rule_with_remediation, resource_key, timeout_s=120)
    assert status["State"] == "SUCCEEDED", (
        f"expected the no-op automation to reach SUCCEEDED, got {status!r}"
    )



def _safe(fn, *gone_codes, busy=()) -> None:
    """Run a teardown call: return on the resource's not-found codes, retry every 2 s the codes AWS
    answers while a dependency is still being released, and raise anything else."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _empty_and_delete_bucket(s3, bucket) -> None:
    """Config writes into its delivery bucket, so remove the objects before the bucket."""
    for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_until_no_failed_items(fn, attempts: int = 8, delay: float = 10.0):
    from botocore.exceptions import ClientError

    last_resp = None
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            resp = fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InsufficientPermissionsException":
                last_exc = exc
                time.sleep(delay)
                continue
            raise
        if not resp.get("FailedItems", []):
            return resp
        last_resp = resp
        time.sleep(delay)
    if last_resp is not None:
        return last_resp
    assert last_exc is not None
    raise last_exc


def _retry(fn, attempts: int = 8, delay: float = 3.0, retry_codes: set[str] | None = None):
    from botocore.exceptions import ClientError

    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if retry_codes is None or code in retry_codes:
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _ensure_configuration_recorder(ctx) -> None:
    config = ctx.client("config")
    if config.describe_configuration_recorders().get("ConfigurationRecorders", []):
        return

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-config-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"), "NoSuchEntity")
    )

    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-config-bucket-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _safe(lambda: _empty_and_delete_bucket(s3, bucket_name), "NoSuchBucket", busy=("BucketNotEmpty",)))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSConfigBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSConfigBucketExistenceCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSConfigBucketDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    recorder_name = ctx.unique_name("sim2real-recorder-")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": recorder_name,
            "roleARN": role_arn,
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
        }
    )
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name), "NoSuchConfigurationRecorderException"))

    channel_name = ctx.unique_name("sim2real-channel-")
    _retry(
        lambda: config.put_delivery_channel(DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}),
        retry_codes={"InsufficientDeliveryPolicyException"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name), "NoSuchDeliveryChannelException"))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: _safe(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name), "NoSuchConfigurationRecorderException"))


def _poll_rule_active(config, rule_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        rules = config.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
        if rules:
            last = rules[0]["ConfigRuleState"]
            if last == "ACTIVE":
                return
        time.sleep(3)
    raise AssertionError(f"config rule {rule_name} never reached ACTIVE, last seen {last!r}")


def _create_automation_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-noop-automation-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _create_noop_document(ctx) -> str:
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-noop-doc-")
    content = {
        "schemaVersion": "0.3",
        "assumeRole": "{{ AutomationAssumeRole }}",
        "parameters": {"AutomationAssumeRole": {"type": "String"}},
        "mainSteps": [{"name": "Wait", "action": "aws:sleep", "inputs": {"Duration": "PT1S"}}],
    }
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(content),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_document(Name=doc_name), "InvalidDocument"))
    return doc_name


def _poll_for_terminal_status_entry(
    config, rule_name: str, resource_key: dict[str, str], timeout_s: float = 120.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    terminal = {"SUCCEEDED", "FAILED"}
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        resp = config.describe_remediation_execution_status(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
        for status in resp.get("RemediationExecutionStatuses", []):
            if status["ResourceKey"].get("resourceId") == resource_key["resourceId"]:
                last = status
                if status["State"] in terminal:
                    return status
        time.sleep(3)
    raise AssertionError(
        f"remediation execution for {rule_name}/{resource_key} never reached a terminal state, "
        f"last seen {last!r}"
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
