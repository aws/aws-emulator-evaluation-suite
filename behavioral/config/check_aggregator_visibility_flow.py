"""aggregator-visibility-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "aggregator-visibility-flow"
GROUP = "e2e"
SERVICES = ["config"]

_CONFIG_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A recorded S3 bucket becomes visible through a self-aggregating configuration aggregator
    (ListAggregateDiscoveredResources / GetAggregateResourceConfig), and queries against the
    aggregator fail with NoSuchConfigurationAggregatorException once it is deleted."""
    _acquire_recorder_lock(ctx)
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    recorder_cleanup = _ensure_recorder(ctx)
    if recorder_cleanup is not None:
        ctx.on_cleanup(recorder_cleanup)

    account_id = sts.get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-aggr-visible-")
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint matching the default region
        # (us-east-1); every other region requires it. Not a hardcoded target region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    _poll_until(
        lambda: cfg.list_discovered_resources(
            resourceType="AWS::S3::Bucket", resourceIds=[bucket_name]
        )["resourceIdentifiers"],
        lambda ids: len(ids) == 1,
        timeout_s=600,
        interval_s=15,
    )

    aggregator_name = ctx.unique_name("sim2real-aggregator-")
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=aggregator_name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AllAwsRegions": False, "AwsRegions": [ctx.region]}
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _delete_configuration_aggregator(cfg, aggregator_name)
    )

    def _bucket_in_aggregate():
        ids = cfg.list_aggregate_discovered_resources(
            ConfigurationAggregatorName=aggregator_name,
            ResourceType="AWS::S3::Bucket",
            Filters={"ResourceName": bucket_name},
        )["ResourceIdentifiers"]
        return [r["ResourceId"] for r in ids]

    found = _poll_until(
        _bucket_in_aggregate,
        lambda ids: bucket_name in ids,
        timeout_s=900,
        interval_s=30,
    )
    assert bucket_name in found, (
        f"expected {bucket_name!r} to appear in the aggregator's discovered resources, got {found!r}"
    )

    from botocore.exceptions import ClientError

    # the aggregator's item read can still answer not-discovered right after the listing shows it
    get_deadline = time.monotonic() + 120.0
    while True:
        try:
            item = cfg.get_aggregate_resource_config(
                ConfigurationAggregatorName=aggregator_name,
                ResourceIdentifier={
                    "SourceAccountId": account_id,
                    "SourceRegion": ctx.region,
                    "ResourceId": bucket_name,
                    "ResourceType": "AWS::S3::Bucket",
                },
            )["ConfigurationItem"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotDiscoveredException" or time.monotonic() > get_deadline:
                raise
        time.sleep(2)
    assert item["resourceId"] == bucket_name, (
        f"expected resourceId={bucket_name!r}, got {item.get('resourceId')!r}"
    )
    assert item["resourceType"] == "AWS::S3::Bucket", (
        f"expected resourceType='AWS::S3::Bucket', got {item.get('resourceType')!r}"
    )

    cfg.delete_configuration_aggregator(ConfigurationAggregatorName=aggregator_name)

    gone = "The configuration aggregator does not exist. Check the configuration aggregator name and try again."
    code, message = _error(
        lambda: cfg.list_aggregate_discovered_resources(
            ConfigurationAggregatorName=aggregator_name,
            ResourceType="AWS::S3::Bucket",
        )
    )
    assert code == "NoSuchConfigurationAggregatorException", (
        f"expected queries against a deleted aggregator to fail, got code={code!r}"
    )
    assert message == gone, message

    redelete_code, redelete_message = _error(
        lambda: cfg.delete_configuration_aggregator(ConfigurationAggregatorName=aggregator_name)
    )
    assert redelete_code == "NoSuchConfigurationAggregatorException", (
        f"expected deleting an already-deleted aggregator to fail, got code={redelete_code!r}"
    )
    assert redelete_message == gone, redelete_message


# ===== helpers =====
def _acquire_recorder_lock(ctx) -> None:
    """AWS Config allows only ONE configuration recorder and ONE delivery
    channel per account/region; since checks in this suite run concurrently
    in the same account, serialize anything that creates/mutates/deletes
    them with a cross-process file lock held for this check's full
    lifetime (registered first so it releases LAST, after every other
    cleanup)."""
    import fcntl

    lock_fd = open("/tmp/sim2real-config-recorder.lock", "a+")
    fcntl.flock(lock_fd, fcntl.LOCK_EX)

    def _release():
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()

    ctx.on_cleanup(_release)


def _error(fn):
    """(code, message) of the expected refusal; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_configuration_aggregator(cfg, name):
    _absent_ok(
        lambda: cfg.delete_configuration_aggregator(ConfigurationAggregatorName=name),
        "NoSuchConfigurationAggregatorException",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _absent_ok(call, *codes):
    """Run a teardown call; return quietly only when AWS reports the resource already gone."""
    from botocore.exceptions import ClientError

    try:
        call()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _delete_channel_of(cfg, recorder_name, channel_name):
    """Stop the recorder first: AWS refuses to delete the last delivery channel of a running one."""
    _absent_ok(
        lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name),
        "NoSuchConfigurationRecorderException",
    )
    _absent_ok(
        lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel_name),
        "NoSuchDeliveryChannelException",
    )


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        # CreateBucket rejects an explicit LocationConstraint matching the default region
        # (us-east-1); every other region requires it. Not a hardcoded target region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
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
    """Ensure a running configuration recorder that records AWS::S3::Bucket
    and has a working delivery channel (AWS Config requires one; an account
    can hold a recorder with no delivery channel, and this helper leaves such
    a pre-existing recorder as it found it).

    Registers cleanup for anything it creates or mutates directly on ``ctx``
    (so a partial failure mid-setup still gets torn down); the caller does
    not need to do anything further with the return value.
    """
    cfg = ctx.client("config")
    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        rec = existing[0]
        recorder_name = rec["name"]
        role_arn = rec["roleARN"]
        original_group = rec.get("recordingGroup")
        status = cfg.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[recorder_name]
        )["ConfigurationRecordersStatus"][0]
        was_recording = bool(status.get("recording"))
        covers_s3 = bool(original_group) and (
            original_group.get("allSupported")
            or "AWS::S3::Bucket" in (original_group.get("resourceTypes") or [])
        )
        has_channel = bool(cfg.describe_delivery_channels().get("DeliveryChannels"))

        if was_recording and covers_s3 and has_channel:
            return None

        if not covers_s3:
            cfg.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )

            def _restore_group():
                cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder_name,
                        "roleARN": role_arn,
                        "recordingGroup": original_group or {"allSupported": True},
                    }
                )

            ctx.on_cleanup(_restore_group)

        if not has_channel:
            sts = ctx.client("sts")
            account_id = sts.get_caller_identity()["Account"]
            bucket, bucket_cleanup = _create_delivery_bucket(ctx, account_id)
            ctx.on_cleanup(bucket_cleanup)
            channel_name = ctx.unique_name("sim2real-channel-")

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
                _delete_channel_of(cfg, recorder_name, channel_name)

            ctx.on_cleanup(_delete_channel)

        if not was_recording or not has_channel:
            cfg.start_configuration_recorder(ConfigurationRecorderName=recorder_name)

            if not was_recording:

                def _restore_stopped():
                    _absent_ok(
                        lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name),
                        "NoSuchConfigurationRecorderException",
                    )

                ctx.on_cleanup(_restore_stopped)

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
        _delete_channel_of(cfg, recorder_name, channel_name)

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
