"""resource-config-history-chronological-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-config-history-chronological-ordering"
GROUP = "ordering"
SERVICES = ["config"]

_CONFIG_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"


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


# ===== helpers =====
def _ensure_recorder_recording(ctx) -> None:
    """Make sure the account has a running Config configuration recorder,
    building the minimal role/bucket/recorder/delivery-channel chain from
    scratch (and tearing it down again) only if none already exists."""
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

    # Config allows exactly one delivery channel per account/region. If one
    # already exists (this branch only runs when describe_configuration_recorders
    # came back empty, so it cannot be in active use by a recorder), adopt it
    # instead of calling PutDeliveryChannel -- this check reads history through
    # the API and never touches the channel's delivered S3 snapshots, so whose
    # bucket it targets is irrelevant.
    existing_channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])

    if not existing_channels:
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

    if not existing_channels:

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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutResourceConfig rejects an unregistered resource type with ValidationException and stores
    nothing, and GetResourceConfigHistory returns a repeatedly-changed bucket's configuration items
    newest-first (the documented default order)."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    # PutResourceConfig checks for a running recorder before it checks the type
    # registry, so the recorder runs first to reach the registration refusal.
    _ensure_recorder_recording(ctx)

    # (1) PutResourceConfig against a resource type nobody has registered is
    # rejected outright -- never silently accepted.
    bogus_type = "Sim2Real::Behavioral::" + ctx.unique_name("Widget").replace("-", "")
    bogus_resource_id = ctx.unique_name("sim2real-bogus-widget-")
    try:
        cfg.put_resource_config(
            ResourceType=bogus_type,
            SchemaVersionId="1-0",
            ResourceId=bogus_resource_id,
            Configuration=json.dumps({"seq": 0}),
        )
        raise AssertionError(f"expected PutResourceConfig with unregistered type {bogus_type!r} to be rejected")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ValidationException", (
            f"expected ValidationException for an unregistered resource type, got "
            f"{exc.response['Error']['Code']!r}"
        )
        expected_message = (
            f"Cannot find registered Resource Type with name {bogus_type}. "
            "Please register the Resource Type with Cloudformation and try again."
        )
        assert exc.response["Error"].get("Message") == expected_message, (
            f"expected {expected_message!r}, got {exc.response['Error'].get('Message')!r}"
        )

    # The rejected write must be a pure no-op: an independent read at the
    # destination (list_discovered_resources) must show nothing was stored.
    discovered = cfg.list_discovered_resources(
        resourceType=bogus_type, resourceIds=[bogus_resource_id]
    )["resourceIdentifiers"]
    assert discovered == [], f"expected no discovered resources for rejected write, got {discovered!r}"

    # (2) Ordering: a real, natively-recorded resource that changes multiple
    # times must have its configuration items returned newest-first.
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-history-bucket-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    def _history():
        try:
            return cfg.get_resource_config_history(resourceType="AWS::S3::Bucket", resourceId=bucket)[
                "configurationItems"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotDiscoveredException":
                return []
            raise

    # A recorder this check just started discovers the bucket on its own schedule, folding any
    # change made before that into one item; the writes start once the first item exists.
    _poll_until(_history, lambda got: len(got) >= 1, timeout_s=900, interval_s=15)

    write_count = 3
    for seq in range(write_count):
        before = len(_history())
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-seq", "Value": str(seq)}]})
        # wait for Config to capture this write as its own item before the next write
        left = ctx.time_left()
        _poll_until(
            _history,
            lambda got, before=before: len(got) > before,
            timeout_s=300.0 if left is None else max(1.0, min(300.0, left - 5.0)),
        )

    items = _poll_until(_history, lambda got: len(got) >= 2, timeout_s=600, interval_s=15)
    assert len(items) >= 2, f"expected at least 2 configuration items for {bucket}, got {len(items)}"

    capture_times = [item["configurationItemCaptureTime"] for item in items]
    assert capture_times == sorted(capture_times, reverse=True), (
        f"configurationItemCaptureTime values are not strictly descending: {capture_times}"
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
