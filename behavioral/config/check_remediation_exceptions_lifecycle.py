"""remediation-exceptions-lifecycle."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "remediation-exceptions-lifecycle"
GROUP = "state-machine"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """Remediation exceptions can be put, listed, and deleted; deleting a nonexistent
    exception raises NoSuchRemediationExceptionException with its exact message.
    """
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    iam = ctx.client("iam")

    _ensure_recorder_running(ctx)

    rule_name = ctx.unique_name("sim2real-remrule-")
    resource_type = "AWS::EC2::Instance"
    message = "sim2real behavioral fidelity check exception"
    expiration = datetime.now(timezone.utc) + timedelta(days=1)

    instance_id = _launch_instance(ctx)
    resource_key = {"ResourceType": resource_type, "ResourceId": instance_id}
    _wait_discovered(config, resource_type, instance_id, timeout_s=_budget_s(ctx, 180.0), interval_s=1.0, ctx=ctx)

    # PutRemediationConfigurations rejects the target as "not valid" unless the rule declares a
    # matching Scope.ComplianceResourceTypes. REQUIRED_TAGS evaluates on configuration change
    # within seconds (EC2_INSTANCE_MANAGED_BY_SSM is effectively periodic-only), and the tag key
    # is one the instance never has, so the instance is guaranteed NON_COMPLIANT.
    config.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Description": "sim2real behavioral fidelity check rule for remediation exceptions",
            "Scope": {"ComplianceResourceTypes": [resource_type]},
            "Source": {"Owner": "AWS", "SourceIdentifier": "REQUIRED_TAGS", "SourceDetails": []},
            "InputParameters": json.dumps({"tag1Key": "sim2real-marker-not-present"}),
        }
    )
    ctx.on_cleanup(lambda: _delete_config_rule_ignoring_missing(config, rule_name))
    _wait_rule_active(config, rule_name, timeout_s=_budget_s(ctx, 60.0), interval_s=1.0, ctx=ctx)
    _wait_evaluated(config, rule_name, instance_id, timeout_s=_budget_s(ctx, 480.0), interval_s=2.0, ctx=ctx)

    role_name = ctx.unique_name("sim2real-remrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignoring_missing(iam, role_name))

    # PutRemediationExceptions rejects a rule with no RemediationConfiguration.
    _put_remediation_configuration_when_role_ready(
        config, rule_name, role_arn, timeout_s=_budget_s(ctx, 90.0), interval_s=2.0, ctx=ctx
    )
    ctx.on_cleanup(lambda: _delete_remediation_configuration_ignoring_missing(config, rule_name))

    put_resp = _poll_until(
        lambda: config.put_remediation_exceptions(
            ConfigRuleName=rule_name,
            ResourceKeys=[resource_key],
            Message=message,
            ExpirationTime=expiration,
        ),
        lambda resp: resp.get("FailedBatches", []) == [],
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2,
        ctx=ctx,
    )
    assert put_resp.get("FailedBatches", []) == [], put_resp

    def _cleanup() -> None:
        try:
            config.delete_remediation_exceptions(
                ConfigRuleName=rule_name, ResourceKeys=[resource_key]
            )
        except config.exceptions.NoSuchRemediationExceptionException:
            pass

    ctx.on_cleanup(_cleanup)

    exceptions = _poll_until(
        lambda: config.describe_remediation_exceptions(ConfigRuleName=rule_name)[
            "RemediationExceptions"
        ],
        lambda items: len(items) == 1,
        timeout_s=_budget_s(ctx, 30.0),
        interval_s=2,
        ctx=ctx,
    )
    assert exceptions[0]["ResourceId"] == instance_id, exceptions[0]
    assert exceptions[0]["ResourceType"] == resource_type, exceptions[0]
    assert exceptions[0]["Message"] == message, exceptions[0]

    del_resp = config.delete_remediation_exceptions(
        ConfigRuleName=rule_name, ResourceKeys=[resource_key]
    )
    assert del_resp.get("FailedBatches", []) == [], del_resp

    _poll_until(
        lambda: config.describe_remediation_exceptions(ConfigRuleName=rule_name)[
            "RemediationExceptions"
        ],
        lambda items: len(items) == 0,
        timeout_s=_budget_s(ctx, 30.0),
        interval_s=2,
        ctx=ctx,
    )

    code, message = _error(
        lambda: config.delete_remediation_exceptions(
            ConfigRuleName=rule_name, ResourceKeys=[resource_key]
        )
    )
    assert code == "NoSuchRemediationExceptionException", code
    assert message == "Specified RemediationException could not be found.", message

    still_empty = config.describe_remediation_exceptions(ConfigRuleName=rule_name)[
        "RemediationExceptions"
    ]
    assert still_empty == [], still_empty


def _launch_instance(ctx) -> str:
    """Launch a real EC2 instance: PutRemediationExceptions rejects a resource id Config
    has never seen with "Could not find resources"."""
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    ami_id = images[0]["ImageId"]

    name_tag = ctx.unique_name("sim2real-remexc-instance-")
    reservation = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    try:
        ec2.get_waiter("instance_running").wait(
            InstanceIds=[instance_id],
            WaiterConfig={"Delay": 1, "MaxAttempts": max(1, int(_budget_s(ctx, 600.0)))},
        )
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"instance {instance_id} running: the run budget ended first; not graded") from None
        raise
    return instance_id


def _wait_discovered(config, resource_type: str, resource_id: str, *, timeout_s=180.0, interval_s=5.0, ctx) -> None:
    """Poll Config's resource inventory until the recorder has discovered resource_id."""
    deadline = time.monotonic() + timeout_s
    while True:
        found = config.list_discovered_resources(
            resourceType=resource_type, resourceIds=[resource_id]
        )["resourceIdentifiers"]
        if found:
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"Config discovering {resource_id}: the run budget ended first; not graded")
            raise AssertionError(
                f"Config never discovered ({resource_type}, {resource_id}) within {timeout_s}s"
            )
        time.sleep(interval_s)


def _wait_rule_active(config, rule_name: str, *, timeout_s=60.0, interval_s=2.0, ctx) -> None:
    _poll_until(
        lambda: config.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0][
            "ConfigRuleState"
        ],
        lambda state: state == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
        ctx=ctx,
    )


def _wait_evaluated(config, rule_name: str, resource_id: str, *, timeout_s=480.0, interval_s=10.0, ctx) -> None:
    """Poll until rule_name has evaluated resource_id: PutRemediationExceptions rejects a
    resource the rule has never evaluated, and a first evaluation can take minutes, so this
    nudges it with an on-demand evaluation."""
    deadline = time.monotonic() + timeout_s
    last_kick = 0.0
    while True:
        results = config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)[
            "EvaluationResults"
        ]
        if any(
            r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"] == resource_id
            for r in results
        ):
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"rule {rule_name} evaluating {resource_id}: the run budget ended first; not graded")
            raise AssertionError(
                f"rule {rule_name} never evaluated resource {resource_id} within {timeout_s}s"
            )
        if time.monotonic() - last_kick > 60.0:
            try:
                config.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
            except ClientError:
                pass
            last_kick = time.monotonic()
        time.sleep(interval_s)


def _ensure_recorder_running(ctx) -> None:
    """Ensure a RECORDING configuration recorder and its delivery channel exist, creating them
    if needed: a recorder that exists but is not started never discovers anything."""
    cfg = ctx.client("config")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    existing_recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing_recorders:
        recorder_name = existing_recorders[0]["name"]
    else:
        role_name = ctx.unique_name("sim2real-cfgrole-")
        bucket_name = ctx.unique_name("sim2real-cfgbucket-").replace("_", "-").lower()
        recorder_name = ctx.unique_name("sim2real-cfgrecorder-")

        trust = json.dumps(
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
        role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
        ctx.on_cleanup(lambda: _delete_role_ignoring_missing(iam, role_name))
        policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

        create_bucket_kwargs: dict[str, Any] = {"Bucket": bucket_name}
        # us-east-1 is S3's own special case: CreateBucket rejects a LocationConstraint there.
        if ctx.region != "us-east-1":
            create_bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
        s3.create_bucket(**create_bucket_kwargs)
        ctx.on_cleanup(lambda: _delete_bucket_ignoring_missing(s3, bucket_name))

        # Buckets created since Apr 2023 default to ACLs disabled, which makes Config's
        # delivery-permission check (a PutObject with bucket-owner-full-control) fail with
        # InsufficientDeliveryPolicyException. Re-enable ACLs.
        s3.put_bucket_ownership_controls(
            Bucket=bucket_name,
            OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]},
        )

        account_id = ctx.client("sts").get_caller_identity()["Account"]
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
                            "Resource": f"arn:aws:s3:::{bucket_name}/*",
                            "Condition": {
                                "StringEquals": {
                                    "s3:x-amz-acl": "bucket-owner-full-control",
                                    "AWS:SourceAccount": account_id,
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
                            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                        }
                    ],
                }
            ),
        )
        ctx.on_cleanup(lambda: _delete_role_policy_ignoring_missing(iam, role_name, "sim2real-config-s3-delivery"))

        def _try_put() -> bool:
            try:
                cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder_name,
                        "roleARN": role_arn,
                        "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                    }
                )
                return True
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "InvalidRoleException":
                    return False
                raise

        _poll_until(_try_put, lambda ok: ok, timeout_s=_budget_s(ctx, 60.0), interval_s=1.0, ctx=ctx)
        ctx.on_cleanup(lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name))

        existing_channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
        if not existing_channels:
            channel_name = ctx.unique_name("sim2real-cfgchannel-")

            def _try_put_channel() -> bool:
                try:
                    cfg.put_delivery_channel(
                        DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}
                    )
                    return True
                except ClientError:
                    return False

            _poll_until(_try_put_channel, lambda ok: ok, timeout_s=_budget_s(ctx, 30.0), interval_s=1.0, ctx=ctx)
            ctx.on_cleanup(lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel_name))

    status = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[recorder_name]
    )["ConfigurationRecordersStatus"][0]
    if not status.get("recording", False):
        cfg.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
        # Stop before the delivery channel and recorder teardowns registered above run:
        # a running recorder blocks deleting the last delivery channel.
        ctx.on_cleanup(
            lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )

    _poll_until(
        lambda: cfg.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[recorder_name]
        )["ConfigurationRecordersStatus"][0].get("recording", False),
        lambda recording: recording,
        timeout_s=_budget_s(ctx, 30.0),
        interval_s=1.0,
        ctx=ctx,
    )


def _put_remediation_configuration_when_role_ready(config, rule_name: str, role_arn: str, *, timeout_s=90.0, interval_s=5.0, ctx) -> None:
    """PutRemediationConfigurations for rule_name, retrying while the just-created IAM role
    has not yet propagated (the service checks the AutomationAssumeRole eagerly)."""
    deadline = time.monotonic() + timeout_s
    remediation_configuration = {
        "ConfigRuleName": rule_name,
        "TargetType": "SSM_DOCUMENT",
        "TargetId": "AWS-StartEC2Instance",
        "Parameters": {
            "InstanceId": {"ResourceValue": {"Value": "RESOURCE_ID"}},
            "AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}},
        },
        "ResourceType": "AWS::EC2::Instance",
        "Automatic": False,
    }
    while True:
        try:
            resp = config.put_remediation_configurations(
                RemediationConfigurations=[remediation_configuration]
            )
            if resp.get("FailedBatches", []):
                raise AssertionError(f"PutRemediationConfigurations failed: {resp['FailedBatches']}")
            return
        except ClientError:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("the remediation role's propagation: the run budget ended first; not graded") from None
                raise
            time.sleep(interval_s)


def _delete_config_rule_ignoring_missing(config, rule_name: str) -> None:
    try:
        config.delete_config_rule(ConfigRuleName=rule_name)
    except config.exceptions.NoSuchConfigRuleException:
        pass


def _delete_role_ignoring_missing(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        pass


def _delete_role_policy_ignoring_missing(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except iam.exceptions.NoSuchEntityException:
        pass


def _delete_bucket_ignoring_missing(s3, bucket_name: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket",):
            raise


def _delete_remediation_configuration_ignoring_missing(config, rule_name: str) -> None:
    try:
        config.delete_remediation_configuration(ConfigRuleName=rule_name)
    except config.exceptions.NoSuchRemediationConfigurationException:
        pass


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, ctx):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the polled condition: the run budget ended first; not graded")
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _error(fn):
    """Call fn(); return the (code, message) of the error it raises. An unexpected success
    raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except Exception as err:  # noqa: BLE001
        response = getattr(err, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
