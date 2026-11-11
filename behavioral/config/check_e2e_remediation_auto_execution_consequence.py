"""e2e-remediation-auto-execution-consequence."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-remediation-auto-execution-consequence"
GROUP = "e2e"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """StartRemediationExecution with the AWS-StartEC2Instance document starts a stopped EC2 instance:
    the execution reaches SUCCEEDED and the instance reaches running; DeleteRemediationConfiguration
    then removes the configuration so a new execution is rejected."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    _ensure_active_recorder(ctx)

    # --- automation role the SSM document assumes to start the instance ---
    role_name = ctx.unique_name("sim2real-remrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="StartInstance",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["ec2:StartInstances", "ec2:DescribeInstances", "ec2:DescribeInstanceStatus"],
                "Resource": "*",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="StartInstance"))

    # --- a real EC2 instance we deliberately stop ---
    image_id = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    image_id.sort(key=lambda i: i["CreationDate"], reverse=True)
    ami_id = image_id[0]["ImageId"]

    name_tag = ctx.unique_name("sim2real-remediation-instance-")
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
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 1, "MaxAttempts": 600})
    ec2.stop_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 1, "MaxAttempts": 600})

    # StartRemediationExecution rejects a ResourceKey Config has not yet discovered --
    # the recorder was only just turned on (or the instance was only just created), so
    # wait for the instance to actually show up in Config's resource inventory.
    _poll_until(
        lambda: config.list_discovered_resources(
            resourceType="AWS::EC2::Instance", resourceIds=[instance_id]
        )["resourceIdentifiers"],
        lambda ids: bool(ids),
        ctx=ctx,
        timeout_s=180,
    )

    # --- a Config rule to attach the remediation configuration to ---
    rule_name = ctx.unique_name("sim2real-remrule-")
    config.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Scope": {"ComplianceResourceTypes": ["AWS::EC2::Instance"], "ComplianceResourceId": instance_id},
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "REQUIRED_TAGS",
                "SourceDetails": [],
            },
            "InputParameters": json.dumps({"tag1Key": "sim2real-marker-not-present"}),
        }
    )
    ctx.on_cleanup(lambda: config.delete_config_rule(ConfigRuleName=rule_name))
    _poll_until(
        lambda: config.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0],
        lambda r: r["ConfigRuleState"] == "ACTIVE",
        ctx=ctx,
        timeout_s=60,
    )

    # StartRemediationExecution rejects a resource key the rule has never evaluated --
    # a fresh rule's initial evaluation is asynchronous, so wait for a real compliance
    # result to exist before treating the rule as ready to remediate against.
    _poll_until(
        lambda: config.get_compliance_details_by_resource(
            ResourceType="AWS::EC2::Instance", ResourceId=instance_id
        )["EvaluationResults"],
        lambda results: any(
            r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ConfigRuleName"] == rule_name
            for r in results
        ),
        ctx=ctx,
        timeout_s=180,
    )

    config.put_remediation_configurations(
        RemediationConfigurations=[{
            "ConfigRuleName": rule_name,
            "TargetId": "AWS-StartEC2Instance",
            "TargetType": "SSM_DOCUMENT",
            "Automatic": False,
            "Parameters": {
                "InstanceId": {"ResourceValue": {"Value": "RESOURCE_ID"}},
                "AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}},
            },
            "ResourceType": "AWS::EC2::Instance",
        }]
    )
    ctx.on_cleanup(lambda: _delete_remediation_quiet(config, rule_name))

    status = _run_remediation_until_success(config, rule_name, instance_id, ctx=ctx, timeout_s=_budget_s(ctx, 300.0))
    assert status["State"] == "SUCCEEDED", f"remediation execution ended in {status}"

    # The actual consequence: the previously-stopped instance is now running.
    described = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0],
        lambda i: i["State"]["Name"] == "running",
        ctx=ctx,
        timeout_s=120,
    )
    assert described["State"]["Name"] == "running", (
        f"expected instance {instance_id} state 'running' after remediation, got {described['State']['Name']!r}"
    )

    config.delete_remediation_configuration(ConfigRuleName=rule_name)
    remaining = config.describe_remediation_configurations(ConfigRuleNames=[rule_name])["RemediationConfigurations"]
    assert remaining == [], "remediation configuration should be gone after DeleteRemediationConfiguration"

    # The delete is unusable, not just absent: starting a new execution against the
    # now-deleted configuration must be specifically rejected, not silently accepted.
    from botocore.exceptions import ClientError

    try:
        config.start_remediation_execution(
            ConfigRuleName=rule_name,
            ResourceKeys=[{"resourceId": instance_id, "resourceType": "AWS::EC2::Instance"}],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "NoSuchRemediationConfigurationException", (
            f"expected NoSuchRemediationConfigurationException after delete, got {code}"
        )
        assert message == (
            f"There is no applicable RemediationConfiguration setup for AWS Config rule {rule_name}"
        ), message
    else:
        raise AssertionError(
            "StartRemediationExecution unexpectedly succeeded after DeleteRemediationConfiguration"
        )



def _delete_remediation_quiet(config, rule_name):
    """Teardown: the body deletes the configuration itself, so an absent one is fine here."""
    from botocore.exceptions import ClientError

    try:
        config.delete_remediation_configuration(ConfigRuleName=rule_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchRemediationConfigurationException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, ctx, timeout_s=60.0, interval_s=1.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _run_remediation_until_success(config, rule_name, instance_id, *, ctx, timeout_s=300.0, interval_s=1.0):
    """Retry StartRemediationExecution while the automation role's trust policy propagates (SSM's
    AssumeRole step fails fast), bounded by timeout_s; any other failure raises immediately."""
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        start_resp = config.start_remediation_execution(
            ConfigRuleName=rule_name,
            ResourceKeys=[{"resourceId": instance_id, "resourceType": "AWS::EC2::Instance"}],
        )
        failed_items = start_resp.get("FailedItems", [])
        if failed_items:
            raise AssertionError(f"StartRemediationExecution rejected the resource key: {failed_items}")
        last_state = None
        while time.monotonic() < deadline:
            rows = config.describe_remediation_execution_status(ConfigRuleName=rule_name)[
                "RemediationExecutionStatuses"
            ]
            if rows and rows[0]["State"] in ("SUCCEEDED", "FAILED"):
                last_state = rows[0]
                break
            time.sleep(interval_s)
        if last_state is None:
            if _budget_spent(ctx):
                raise TimeoutError("a terminal remediation execution state: the run budget ended first; not graded")
            raise AssertionError(
                f"remediation execution never reached a terminal state within {timeout_s}s"
            )
        if last_state["State"] == "SUCCEEDED":
            return last_state
        detail = json.dumps(last_state.get("StepDetails", last_state), default=str)
        if "AssumeRole" not in detail and "AccessDenied" not in detail:
            raise AssertionError(f"remediation execution failed for a non-propagation reason: {last_state}")
    if _budget_spent(ctx):
        raise TimeoutError("a succeeded remediation execution: the run budget ended first; not graded")
    raise AssertionError(f"remediation execution never succeeded within {timeout_s}s (last observed: {last_state!r})")


def _ensure_active_recorder(ctx):
    config = ctx.client("config")

    existing = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        name = existing[0]["name"]
        status = config.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[name]
        )["ConfigurationRecordersStatus"][0]
        if status.get("recording"):
            return name, False
        channels = config.describe_delivery_channels().get("DeliveryChannels", [])
        if channels:
            config.start_configuration_recorder(ConfigurationRecorderName=name)
            return name, False

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    name = ctx.unique_name("sim2real-cfghelper-rec-")
    bucket = ctx.unique_name("sim2real-cfghelper-bkt-").lower()
    region = ctx.region
    if region == "us-east-1":
        # not a region pin -- S3's CreateBucket rejects an explicit LocationConstraint
        # of us-east-1 itself, so the constraint must be omitted only in that one case.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

    def _empty_and_delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)

    role_name = ctx.unique_name("sim2real-cfghelper-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
        )
    )
    account_id = sts.get_caller_identity()["Account"]
    bucket_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/Config/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    })
    s3.put_bucket_policy(Bucket=bucket, Policy=bucket_policy)

    # Config validates the role's trust policy (and, on start, the bucket policy) while both
    # may still be propagating, so retry those two calls specifically.
    _retry_role_propagation(
        lambda: config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": name,
                "roleARN": role_arn,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }
        )
    )
    ctx.on_cleanup(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=name))
    _retry_role_propagation(
        lambda: config.put_delivery_channel(DeliveryChannel={"name": name, "s3BucketName": bucket})
    )
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=name))
    _retry_role_propagation(lambda: config.start_configuration_recorder(ConfigurationRecorderName=name))
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=name))
    return name, True


def _retry_role_propagation(fn, *, timeout_s=60.0, interval_s=2.0):
    """Retries a call that Config validates against a role trust policy or bucket policy
    that may still be propagating through IAM/S3's eventual consistency window."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("InvalidRoleException", "InsufficientDeliveryPolicyException", "AccessDeniedException", "AccessDenied"):
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err


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
