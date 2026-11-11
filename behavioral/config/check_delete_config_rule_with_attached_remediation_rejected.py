"""delete-config-rule-with-attached-remediation-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-config-rule-with-attached-remediation-rejected"
GROUP = "e2e"
SERVICES = ["config"]

_CONFIG_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """DeleteConfigRule fails with ResourceInUseException while a remediation configuration is attached,
    leaving both intact; deleting the remediation first makes the rule deletable. Unicode, emoji,
    quotes/backslashes and empty tag values survive PutConfigRule/TagResource byte-for-byte."""
    _acquire_recorder_lock(ctx)
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")

    recorder_cleanup = _ensure_recorder(ctx)
    if recorder_cleanup is not None:
        ctx.on_cleanup(recorder_cleanup)

    rule_name = ctx.unique_name("sim2real-inuse-rule-")
    description = (
        'Pipeline \u201c\u6570\u636e\u7ba1\u9053\u201d \U0001f680 with a "quoted" segment, '
        'a backslash \\ and a literal newline-as-text: \\n end.'
    )
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Description": description,
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
        }
    )
    rule_deleted = False

    def _teardown_rule():
        if rule_deleted:
            return
        try:
            cfg.delete_remediation_configuration(ConfigRuleName=rule_name)
        except cfg.exceptions.NoSuchRemediationConfigurationException:
            pass
        cfg.delete_config_rule(ConfigRuleName=rule_name)

    ctx.on_cleanup(_teardown_rule)

    # PutConfigRule returns before the rule is fully materialized (it starts
    # in ConfigRuleState=CREATING); wait for ACTIVE before doing anything
    # that references it, since a not-yet-active rule is exactly what
    # produces "remediation target ... could not be found" below.
    def _rule_state():
        rules = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
        return rules[0]["ConfigRuleState"] if rules else None

    state = _poll_until(
        _rule_state,
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    assert state == "ACTIVE", f"expected the new rule to reach ACTIVE, got {state!r}"

    described = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0]
    assert described["Description"] == description, (
        f"Description round-trip mismatch: {described['Description']!r} != {description!r}"
    )
    rule_arn = described["ConfigRuleArn"]

    repr_tags = [
        {"Key": "designation", "Value": "\u6570\u636e\u56e2\u961f"},
        {"Key": "note", "Value": "path/like:value=test+ok.1_2@x"},
        {"Key": "empty-value", "Value": ""},
    ]
    cfg.tag_resource(ResourceArn=rule_arn, Tags=repr_tags)
    fetched_tags = {
        t["Key"]: t["Value"]
        for t in cfg.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]
    }
    for tag in repr_tags:
        assert fetched_tags.get(tag["Key"]) == tag["Value"], (
            f"tag {tag['Key']!r} round-trip mismatch: "
            f"{fetched_tags.get(tag['Key'])!r} != {tag['Value']!r}"
        )
    cfg.untag_resource(ResourceArn=rule_arn, TagKeys=[t["Key"] for t in repr_tags])
    after_untag = cfg.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]
    assert after_untag == [], f"expected no tags after UntagResource, got {after_untag}"

    remediation_role_arn, remediation_role_cleanup = _create_remediation_role(ctx)
    ctx.on_cleanup(remediation_role_cleanup)

    # Even ACTIVE, PutRemediationConfigurations can lag briefly behind rule
    # creation with InvalidParameterValueException ("remediation target ...
    # could not be found"), so retry through that residual propagation lag.
    put_deadline = time.monotonic() + 200
    left = ctx.time_left()
    if left is not None:
        put_deadline = min(put_deadline, time.monotonic() + left)
    while True:
        try:
            cfg.put_remediation_configurations(
                RemediationConfigurations=[
                    {
                        "ConfigRuleName": rule_name,
                        "TargetType": "SSM_DOCUMENT",
                        "TargetId": "AWS-ConfigureS3BucketVersioning",
                        "Automatic": False,
                        "Parameters": {
                            "AutomationAssumeRole": {"StaticValue": {"Values": [remediation_role_arn]}},
                            "BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}},
                        },
                    }
                ]
            )
            break
        except cfg.exceptions.InvalidParameterValueException:
            if time.monotonic() > put_deadline:
                raise
            time.sleep(2)

    code, message = _error_code(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException deleting a rule with an attached "
        f"remediation configuration, got {code!r}"
    )
    assert message == (
        f"The rule {rule_name} currently has a RemediationConfiguration. "
        "Please delete the RemediationConfiguration and try again."
    ), message

    # The effect must be absent: the rule is still there.
    names = [
        r["ConfigRuleName"]
        for r in cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
    ]
    assert rule_name in names, "rule disappeared despite the rejected delete"

    # Positive control: remove the remediation configuration first, then the same delete succeeds.
    cfg.delete_remediation_configuration(ConfigRuleName=rule_name)
    cfg.delete_config_rule(ConfigRuleName=rule_name)
    rule_deleted = True

    # DeleteConfigRule is asynchronous (the rule transitions through a
    # DELETING state before it actually disappears), so poll rather than
    # checking immediately.
    def _still_present():
        try:
            rules = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
        except cfg.exceptions.NoSuchConfigRuleException:
            return False
        return bool(rules)

    gone = _poll_until(
        _still_present,
        lambda present: present is False,
        timeout_s=120,
        interval_s=5,
    )
    assert gone is False, "rule still present after a successful delete"


def _acquire_recorder_lock(ctx) -> None:
    """AWS Config allows one configuration recorder and one delivery channel per account/region;
    serialize changes to them with a cross-process file lock held for the check's lifetime
    (registered first so it releases last, after every other cleanup)."""
    import fcntl

    lock_fd = open("/tmp/sim2real-config-recorder.lock", "a+")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)

    def _release():
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()

    ctx.on_cleanup(_release)


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _create_remediation_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-inuse-remediation-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ssm.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]

    def cleanup():
        _absent_ok(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")

    return role_arn, cleanup


def _absent_ok(call, *codes):
    """Run a teardown call; return quietly only when AWS reports the resource already gone."""
    from botocore.exceptions import ClientError

    try:
        call()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _create_config_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-config-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CONFIG_ROLE_POLICY_ARN)

    def cleanup():
        _absent_ok(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_CONFIG_ROLE_POLICY_ARN),
            "NoSuchEntity",
        )
        _absent_ok(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")

    return role_arn, cleanup


def _create_delivery_bucket(ctx, account_id):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfg-delivery-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    policy = {
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
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    def cleanup():
        from botocore.exceptions import ClientError

        # Config can still deliver a file just after its channel goes: re-empty on BucketNotEmpty.
        deadline = time.monotonic() + 60
        while True:
            try:
                for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
                s3.delete_bucket(Bucket=bucket)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchBucket":
                    return
                if code != "BucketNotEmpty" or time.monotonic() > deadline:
                    raise
            time.sleep(2)

    return bucket, cleanup


def _ensure_recorder(ctx):
    """Ensure a running configuration recorder (any scope: the rule is never evaluated, PutConfigRule
    only needs one to exist). Registers cleanup on ``ctx`` for anything it creates."""
    cfg = ctx.client("config")
    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        return None

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_arn, role_cleanup = _create_config_role(ctx)
    ctx.on_cleanup(role_cleanup)
    bucket, bucket_cleanup = _create_delivery_bucket(ctx, account_id)
    ctx.on_cleanup(bucket_cleanup)
    recorder_name = ctx.unique_name("sim2real-recorder-")
    channel_name = ctx.unique_name("sim2real-channel-")

    last_err = None
    for _ in range(8):
        try:
            cfg.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )
            last_err = None
            break
        except Exception as exc:  # IAM role propagation lag
            last_err = exc
            time.sleep(5)
    if last_err is not None:
        raise last_err

    def _delete_recorder():
        _absent_ok(
            lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name),
            "NoSuchConfigurationRecorderException",
        )
        _absent_ok(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name),
            "NoSuchConfigurationRecorderException",
        )

    ctx.on_cleanup(_delete_recorder)

    last_err = None
    for _ in range(8):
        try:
            cfg.put_delivery_channel(
                DeliveryChannel={"name": channel_name, "s3BucketName": bucket}
            )
            last_err = None
            break
        except Exception as exc:  # IAM role trust/bucket-policy propagation lag
            last_err = exc
            time.sleep(5)
    if last_err is not None:
        raise last_err

    def _delete_channel():
        # The last delivery channel cannot be deleted while the recorder runs, and this
        # step runs before _delete_recorder, so stop the recorder first.
        _absent_ok(
            lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name),
            "NoSuchConfigurationRecorderException",
        )
        _absent_ok(
            lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel_name),
            "NoSuchDeliveryChannelException",
        )

    ctx.on_cleanup(_delete_channel)

    cfg.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    return None


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
