"""deploy-configuration-recorder-cloudformation-actually-records."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-configuration-recorder-cloudformation-actually-records"
GROUP = "deploy"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A CloudFormation-deployed ConfigurationRecorder really records: after StartConfigurationRecorder,
    tagging the stack's own S3 bucket shows up in GetResourceConfigHistory, while a never-touched
    bucket name has no history."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    if config.describe_configuration_recorders().get("ConfigurationRecorders", []):
        raise AssertionError(
            "a configuration recorder already exists in this account/region; only "
            "one customer-managed recorder is allowed per account/region so this "
            "check cannot safely provision its own via CloudFormation without "
            "disturbing the account's existing baseline"
        )

    stack_name = ctx.unique_name("sim2real-recorder-stack-")
    role_name = ctx.unique_name("sim2real-recorder-role-")
    recorder_name = ctx.unique_name("sim2real-recorder-")
    channel_name = ctx.unique_name("sim2real-channel-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ConfigBucket": {"Type": "AWS::S3::Bucket"},
            "ConfigBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "ConfigBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSConfigBucketPermissionsCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "config.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}"},
                                "Condition": {"StringEquals": {"AWS:SourceAccount": {"Ref": "AWS::AccountId"}}},
                            },
                            {
                                "Sid": "AWSConfigBucketExistenceCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "config.amazonaws.com"},
                                "Action": "s3:ListBucket",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}"},
                                "Condition": {"StringEquals": {"AWS:SourceAccount": {"Ref": "AWS::AccountId"}}},
                            },
                            {
                                "Sid": "AWSConfigBucketDelivery",
                                "Effect": "Allow",
                                "Principal": {"Service": "config.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}/AWSLogs/${AWS::AccountId}/Config/*"},
                                "Condition": {"StringEquals": {"AWS:SourceAccount": {"Ref": "AWS::AccountId"}}},
                            },
                        ],

                    },
                },
            },
            "ConfigRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"],
                },
            },
            "Recorder": {
                "Type": "AWS::Config::ConfigurationRecorder",
                "DependsOn": "ConfigRole",
                "Properties": {
                    "Name": recorder_name,
                    "RoleARN": {"Fn::GetAtt": ["ConfigRole", "Arn"]},
                    "RecordingGroup": {"AllSupported": True, "IncludeGlobalResourceTypes": False},
                },
            },
        },
    }

    _create_stack(ctx, stack_name, template)

    # Don't block on the full CloudFormation stack reaching CREATE_COMPLETE --
    # AWS::Config::ConfigurationRecorder stabilization inside CloudFormation can
    # run long. Instead, poll Config directly for the actual resource this check
    # cares about, bailing out fast if the stack rolls back.
    recorders = _poll_recorder_exists(ctx, stack_name, config, recorder_name, timeout_s=120)
    assert len(recorders) == 1, f"expected exactly 1 recorder named {recorder_name!r}, got {recorders!r}"
    assert recorders[0]["name"] == recorder_name, (
        f"expected recorder name {recorder_name!r}, got {recorders[0]['name']!r}"
    )

    bucket_name = _poll_bucket_physical_id(ctx, stack_name, "ConfigBucket", timeout_s=60)

    # The delivery channel is required before a recorder can start, but the
    # CFN AWS::Config::DeliveryChannel resource type is known to stabilize very
    # slowly (well beyond this check's budget); create it directly instead --
    # this still proves the CloudFormation-deployed recorder is real and active.
    _retry(
        lambda: config.put_delivery_channel(DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}),
        retry_codes={"InsufficientDeliveryPolicyException"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name), "NoSuchDeliveryChannelException"))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: _safe(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name), "NoSuchConfigurationRecorderException"))
    _poll_recorder_running(config, recorder_name, timeout_s=20)

    resource_type = "AWS::S3::Bucket"
    marker = ctx.unique_name("sim2real-marker-")

    # Negative control: a bucket that was never touched by this recorder (a
    # syntactically valid but nonexistent name) has no history -- proving the
    # positive result below isn't fabricated.
    never_recorded_id = ctx.unique_name("sim2real-never-recorded-bucket-").lower()
    history_code, history_message = _error(
        lambda: config.get_resource_config_history(resourceType=resource_type, resourceId=never_recorded_id)
    )
    assert history_code == "ResourceNotDiscoveredException", (
        f"expected ResourceNotDiscoveredException for never-recorded bucket {never_recorded_id!r}, "
        f"got {history_code!r}"
    )
    assert history_message == (
        f"Resource {never_recorded_id} of resourceType:{resource_type} is unknown or has not been "
        "discovered"
    ), history_message

    # Trigger a real, recordable configuration change on the bucket the stack
    # itself created, now that the CloudFormation-deployed recorder is running.
    # Merge with any existing (e.g. CloudFormation system) tags -- PutBucketTagging
    # replaces the whole tag set and rejects removing system tags outright.
    s3 = ctx.client("s3")
    try:
        existing_tags = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
    except Exception:
        existing_tags = []
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": existing_tags + [{"Key": "sim2real-marker", "Value": marker}]},
    )

    item = _poll_resource_history_tagged(config, resource_type, bucket_name, marker, timeout_s=150)
    assert item["resourceId"] == bucket_name, f"expected resourceId {bucket_name!r}, got {item['resourceId']!r}"
    assert item["resourceType"] == resource_type, (
        f"expected resourceType {resource_type!r}, got {item['resourceType']!r}"
    )
    recorded_marker = (item.get("tags") or {}).get("sim2real-marker")
    assert recorded_marker == marker, (
        f"expected recorded sim2real-marker tag {marker!r} on {bucket_name!r}, got {recorded_marker!r}"
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
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_stack(ctx, stack_name: str, template: dict[str, Any]) -> None:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))


def _stack_failure_reason(ctx, stack_name: str) -> str | None:
    cfn = ctx.client("cloudformation")
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except Exception:
        return None
    if not stacks:
        return None
    status = stacks[0]["StackStatus"]
    if "ROLLBACK" in status or status.endswith("FAILED"):
        return f"{status}: {stacks[0].get('StackStatusReason')}"
    return None


def _retry(fn, attempts: int = 8, delay: float = 5.0, retry_codes: set[str] | None = None):
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
    assert last_exc is not None, "retry loop exhausted attempts without recording an exception"
    raise last_exc


def _poll_stack_output(ctx, stack_name: str, output_key: str, timeout_s: float = 60.0) -> str:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])} if stacks else {}
        if output_key in outputs:
            return outputs[output_key]
        time.sleep(3)
    raise AssertionError(f"stack {stack_name} never published output {output_key!r}")


def _poll_bucket_physical_id(ctx, stack_name: str, logical_id: str, timeout_s: float = 60.0) -> str:
    """Ask CloudFormation for the bucket's physical ID directly: the bucket finishes long before the
    stack, whose Outputs only populate once every resource reports CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resource = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)[
                "StackResourceDetail"
            ]
        except Exception:
            resource = None
        if resource:
            last_status = resource.get("ResourceStatus")
            physical_id = resource.get("PhysicalResourceId")
            if physical_id and last_status in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
                return physical_id
        time.sleep(3)
    raise AssertionError(f"stack {stack_name} resource {logical_id} never completed, last status {last_status!r}")


def _poll_recorder_exists(ctx, stack_name: str, config, recorder_name: str, timeout_s: float = 180.0) -> list:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        failure = _stack_failure_reason(ctx, stack_name)
        if failure:
            raise AssertionError(f"stack {stack_name} failed before recorder appeared: {failure}")
        try:
            recorders = config.describe_configuration_recorders(ConfigurationRecorderNames=[recorder_name])[
                "ConfigurationRecorders"
            ]
            if recorders:
                return recorders
        except Exception as exc:
            last_exc = exc
        time.sleep(5)
    raise AssertionError(f"configuration recorder {recorder_name} never appeared via CloudFormation: {last_exc}")


def _poll_recorder_running(config, recorder_name: str, timeout_s: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        statuses = config.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[recorder_name]
        )["ConfigurationRecordersStatus"]
        if statuses:
            last = statuses[0]
            if last.get("recording"):
                return last
        time.sleep(3)
    raise AssertionError(f"configuration recorder {recorder_name} never reached recording=True, last seen {last!r}")


def _poll_resource_history_tagged(config, resource_type: str, resource_id: str, marker: str, timeout_s: float = 150.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    last_item = None
    while time.monotonic() < deadline:
        try:
            resp = config.get_resource_config_history(resourceType=resource_type, resourceId=resource_id)
            items = resp.get("configurationItems", [])
            if items:
                last_item = items[0]
                tags = last_item.get("tags") or {}
                if tags.get("sim2real-marker") == marker:
                    return last_item
        except Exception as exc:
            last_exc = exc
        time.sleep(5)
    if last_item is not None:
        return last_item
    raise AssertionError(f"resource config history for {resource_id} never appeared: {last_exc}")


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

    def _gone_too(fn):
        # the stack's own deletion may remove a recorder or channel while this runs
        try:
            _call(fn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("NoSuchConfigurationRecorderException", "NoSuchDeliveryChannelException"):
                raise

    def _restore() -> None:
        now = _recorders()
        for r in now:
            _gone_too(lambda n=r["name"]: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        kept = {c["name"] for c in channels}
        for c in _call(cfg.describe_delivery_channels)["DeliveryChannels"]:
            if c["name"] not in kept:
                _gone_too(lambda n=c["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
        kept = {r["name"] for r in recorders}
        for r in now:
            if r["name"] not in kept:
                _gone_too(lambda n=r["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
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
