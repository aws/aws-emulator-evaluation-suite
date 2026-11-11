"""deploy-config-delivery-channel-by-cloudformation-delivers-a-snapshot-containing-the-recorded-item."""

from __future__ import annotations

import gzip
import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_CFN_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "sim2real behavioral fidelity probe: AWS Config delivery infrastructure",
    "Resources": {
        "ConfigBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "Tags": [{"Key": "sim2real", "Value": "config-cfn-snapshot-delivery"}]
            },
        },
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
                        },
                        {
                            "Sid": "AWSConfigBucketExistenceCheck",
                            "Effect": "Allow",
                            "Principal": {"Service": "config.amazonaws.com"},
                            "Action": "s3:ListBucket",
                            "Resource": {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}"},
                        },
                        {
                            "Sid": "AWSConfigBucketDelivery",
                            "Effect": "Allow",
                            "Principal": {"Service": "config.amazonaws.com"},
                            "Action": "s3:PutObject",
                            "Resource": {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}/*"},
                            "Condition": {
                                "StringEquals": {
                                    "s3:x-amz-acl": "bucket-owner-full-control"
                                }
                            },
                        },
                    ],
                },
            },
        },
        "ConfigRecorderRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "config.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "ManagedPolicyArns": [
                    "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
                ],
                "Policies": [
                    {
                        "PolicyName": "sim2real-config-delivery",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:PutObject",
                                        "s3:GetBucketAcl",
                                        "s3:ListBucket",
                                    ],
                                    "Resource": [
                                        {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}"},
                                        {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}/*"},
                                    ],
                                }
                            ],
                        },
                    }
                ],
                "Tags": [
                    {"Key": "sim2real", "Value": "config-cfn-snapshot-delivery"}
                ],
            },
        },
    },
    "Outputs": {
        "BucketName": {"Value": {"Ref": "ConfigBucket"}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["ConfigRecorderRole", "Arn"]}},
    },
}

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit and trips ThrottlingException; retry
    # only that, re-raising any domain error.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition",
                ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _clear_recorders(ctx):
    """There is one configuration recorder per account and Region, so a leftover recorder turns
    PutConfigurationRecorder into MaxNumberOfConfigurationRecordersExceededException."""
    cfg = ctx.client("config")
    try:
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except ClientError:
        return
    for rec in recs:
        name = rec.get("name")
        try:
            _retry_throttled(
                lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n)
            )
        except ClientError:
            pass
        try:
            _retry_throttled(
                lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n)
            )
        except ClientError:
            pass


def _clear_delivery_channels(ctx):
    cfg = ctx.client("config")
    try:
        chans = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    except ClientError:
        return
    for ch in chans:
        try:
            cfg.delete_delivery_channel(DeliveryChannelName=ch.get("name"))
        except ClientError:
            pass


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    # A versioned bucket needs every version AND every delete marker removed, else
    # delete_bucket fails BucketNotEmpty; list_objects_v2 alone never sees them.
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", [])):
                try:
                    s3.delete_object(
                        Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"]
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                try:
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_bucket(ctx, ctx_prefix, scenario):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(ctx_prefix).replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's default region and CreateBucket rejects an explicit LocationConstraint
    # naming it; every other region requires one. Not a check-specific region pin.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]}
    )
    return bucket


def _create_recorder(ctx, name, role_arn, recording_group=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn,
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    # PutConfigurationRecorder validates that Config can assume the role, which fails until a
    # freshly created role has propagated.
    last = None
    for attempt in range(8):
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder)
            )
            ctx.on_cleanup(
                lambda: _retry_throttled(
                    lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
                )
            )
            return name
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InsufficientPermissionsException", "AccessDeniedException"):
                raise
            last = exc
            time.sleep(5 * (attempt + 1))
    raise last


def _recorder_status(ctx, name):
    cfg = ctx.client("config")
    statuses = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[name]
    ).get("ConfigurationRecordersStatus", [])
    return statuses[0] if statuses else None


def _start_recorder(ctx, name, register_cleanup=True):
    """Start the recorder and wait until it reports recording=True. Not gated on lastStatus
    SUCCESS: on AWS it stays PENDING for over 300s on a fresh recorder while items are produced."""
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name))
    if register_cleanup:
        ctx.on_cleanup(
            lambda: _retry_throttled(
                lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name)
            )
        )
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is True,
        timeout_s=_budget_s(ctx, 90),
        ctx=ctx,
        interval_s=2,
        description=f"recorder {name!r} reports recording=True",
    )


def _create_delivery_channel(ctx, name, bucket):
    cfg = ctx.client("config")
    channel = {"name": name, "s3BucketName": bucket}
    # The freshly-written bucket policy is eventually consistent; Config rejects a
    # delivery channel whose bucket policy has not propagated with
    # InsufficientDeliveryPolicyException.
    last = None
    for attempt in range(8):
        try:
            _retry_throttled(lambda: cfg.put_delivery_channel(DeliveryChannel=channel))
            ctx.on_cleanup(
                lambda: _retry_throttled(
                    lambda: cfg.delete_delivery_channel(DeliveryChannelName=name)
                )
            )
            return name
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "InsufficientDeliveryPolicyException":
                raise
            last = exc
            time.sleep(3 * (attempt + 1))
    raise last


def _await_history_items(ctx, resource_type, resource_id, *, timeout_s, predicate=None,
                         description=None):
    """Poll for configuration items; on timeout report the recorder status too, so a stalled
    recorder is distinguishable from an unrecorded resource."""
    predicate = predicate or (lambda items: bool(items))
    description = description or f"a configuration item for {resource_type} {resource_id!r}"
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _history_items(ctx, resource_type, resource_id)
        if predicate(last):
            return last
        time.sleep(min(2, max(0.0, deadline - time.monotonic())))
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}. Recorder status: "
        f"{_all_recorder_statuses(ctx)!r}"
    )


def _all_recorder_statuses(ctx):
    cfg = ctx.client("config")
    try:
        return [
            {k: s.get(k) for k in ("name", "recording", "lastStatus", "lastErrorCode",
                                   "lastErrorMessage")}
            for s in cfg.describe_configuration_recorder_status()[
                "ConfigurationRecordersStatus"]
        ]
    except ClientError as exc:
        return f"unreadable: {exc}"


def _history_items(ctx, resource_type, resource_id):
    """Every configuration item Config holds for a resource, paginated. An
    ResourceNotDiscoveredException means Config has recorded nothing for it, which is an
    empty history rather than an error for polling purposes."""
    cfg = ctx.client("config")
    items = []
    try:
        for page in cfg.get_paginator("get_resource_config_history").paginate(
            resourceType=resource_type, resourceId=resource_id
        ):
            items.extend(page.get("configurationItems", []))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotDiscoveredException":
            return []
        raise
    return items


def _bucket_keys(ctx, bucket):
    s3 = ctx.client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _stack_failure_reasons(ctx, stack):
    cfn = ctx.client("cloudformation")
    out = []
    try:
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
            out.extend(
                (e["LogicalResourceId"], e.get("ResourceStatusReason"))
                for e in page.get("StackEvents", [])
                if e.get("ResourceStatus", "").endswith("_FAILED")
            )
    except ClientError:
        pass
    return out


def _delete_stack(ctx, stack):
    """Empty the stack's buckets, then DeleteStack and wait. DeleteStack fails on a non-empty
    bucket, and Config keeps writing into the delivery bucket for a short while after the recorder
    stops, so the empty-then-delete is retried rather than attempted once."""
    cfn = ctx.client("cloudformation")
    try:
        buckets = [
            r["PhysicalResourceId"]
            for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
            if r["ResourceType"] == "AWS::S3::Bucket"
        ]
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise
        return
    for attempt in range(3):
        for bucket in buckets:
            _empty_and_delete_bucket(ctx, bucket)
        try:
            cfn.delete_stack(StackName=stack)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
            )
            return
        except Exception as exc:  # noqa: BLE001 - re-raised
            if attempt == 2:
                raise RuntimeError(f"could not delete stack {stack!r}: {exc}") from exc
            time.sleep(2)


CHECK = "deploy-config-delivery-channel-by-cloudformation-delivers-a-snapshot-containing-the-recorded-item"
GROUP = 'deploy'
SERVICES = ['cloudformation', 'config', 's3']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """DeliverConfigSnapshot into a CloudFormation-provisioned bucket reaches SUCCESS and writes a
    gzipped object under AWSLogs/<account>/Config/<region>/ keyed by the snapshot id, whose
    configurationItems include the bucket this check created.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    scenario = "config-cfn-snapshot-delivery"

    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)

    stack = ctx.unique_name("sim2real-behav-cfg-stack-")
    cfn.create_stack(
        StackName=stack,
        TemplateBody=json.dumps(_CFN_TEMPLATE),
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    # Registered right after the create it undoes, before anything else, so it runs last:
    # DeleteStack fails on a non-empty bucket, so the callable empties the stack's bucket first and
    # re-empties on retry (Config keeps writing for a short while after the recorder stops).
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack))

    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith("_COMPLETE") or s.endswith("_FAILED"),
        timeout_s=_budget_s(ctx, 420),
        ctx=ctx,
        interval_s=2,
        description=f"stack {stack!r} reaches a terminal status",
    )
    assert status == "CREATE_COMPLETE", (
        f"the delivery infrastructure stack did not deploy: {status!r} "
        f"({_stack_failure_reasons(ctx, stack)!r})"
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    }
    bucket, role_arn = outputs["BucketName"], outputs["RoleArn"]
    physical = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
    }
    assert physical["ConfigBucket"] == bucket, (physical, outputs)

    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder, role_arn=role_arn)
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket)
    _start_recorder(ctx, recorder)

    observed = _create_bucket(ctx, "sim2real-behav-cfg-observed-", scenario)
    items = _await_history_items(
        ctx,
        "AWS::S3::Bucket",
        observed,
        timeout_s=_budget_s(ctx, 500),
        description=f"a configuration item for bucket {observed!r}",
    )
    observed_arn = items[-1]["arn"]
    assert observed_arn.endswith(observed), (observed_arn, observed)

    snapshot_id = _retry_throttled(
        lambda: cfg.deliver_config_snapshot(deliveryChannelName=channel)
    )["configSnapshotId"]
    info = _poll_until(
        lambda: cfg.describe_delivery_channel_status(DeliveryChannelNames=[channel])[
            "DeliveryChannelsStatus"
        ][0].get("configSnapshotDeliveryInfo", {}),
        lambda i: i.get("lastStatus") == "SUCCESS",
        timeout_s=_budget_s(ctx, 420),
        ctx=ctx,
        interval_s=2,
        description="snapshot delivery reaches SUCCESS",
    )
    assert info.get("lastStatus") == "SUCCESS", (
        f"snapshot delivery did not succeed: {info!r}"
    )

    keys = _poll_until(
        lambda: _bucket_keys(ctx, bucket),
        lambda ks: any(snapshot_id in k for k in ks),
        timeout_s=_budget_s(ctx, 420),
        ctx=ctx,
        interval_s=2,
        description=f"a delivered object whose key contains configSnapshotId {snapshot_id!r}",
    )
    key = next(k for k in keys if snapshot_id in k)
    assert key.startswith(f"AWSLogs/{account}/Config/{ctx.region}/"), (
        f"unexpected delivery prefix for {key!r}; bucket held {keys!r}"
    )

    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body[:2] == b"\x1f\x8b", (
        f"the delivered object is not gzipped: {body[:8]!r}"
    )
    doc = json.loads(gzip.decompress(body).decode("utf-8"))
    assert "configurationItems" in doc, sorted(doc)

    snapshot_items = doc["configurationItems"]
    arns = [i.get("ARN") for i in snapshot_items]
    assert observed_arn in arns, (
        f"the recorded bucket {observed!r} ({observed_arn!r}) is missing from the delivered "
        f"snapshot; the snapshot held {len(snapshot_items)} items covering "
        f"{sorted({i.get('resourceType') for i in snapshot_items})!r}"
    )
    snapshot_item = next(i for i in snapshot_items if i.get("ARN") == observed_arn)
    assert snapshot_item["resourceId"] == observed, snapshot_item
    assert snapshot_item["awsRegion"] == ctx.region, snapshot_item


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
