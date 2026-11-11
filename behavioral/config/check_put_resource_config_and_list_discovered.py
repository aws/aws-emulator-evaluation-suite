"""put-resource-config-and-list-discovered."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-config-and-list-discovered"
GROUP = "resource-config"
SERVICES = ["config"]


_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "Throttling")
_CONFIG_ROLE_NAME = "sim2real-behav-config-role"
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_CONFIG_TRUST_POLICY = json.dumps(
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


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    """Call *fn*, retrying AWS Config throttling with exponential backoff; domain errors re-raise."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


def _retry_on(fn, codes, attempts=10, base_delay=3.0):
    """Call *fn*, retrying while it raises one of *codes*: Config's view of a just-created bucket and
    bucket policy lags S3, so PutDeliveryChannel can transiently report NoSuchBucket."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in codes:
                raise
            last = exc
            time.sleep(base_delay * (1 + min(attempt, 4)))
    raise last


def _absent_ok(fn, *codes):
    """Run a teardown call; return quietly only when AWS reports the resource already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "") not in codes:
            raise


def _delete_recorder_quiet(ctx, name):
    cfg = ctx.client("config")
    for call in (cfg.stop_configuration_recorder, cfg.delete_configuration_recorder):
        _absent_ok(
            lambda call=call: _retry_throttled(lambda: call(ConfigurationRecorderName=name)),
            "NoSuchConfigurationRecorderException",
        )


def _delete_channel_quiet(ctx, name):
    # Cleanups run last-in first-out, so this runs while the recorder is still
    # recording; AWS refuses to delete the last channel of a running recorder.
    cfg = ctx.client("config")
    for rec in cfg.describe_configuration_recorders().get("ConfigurationRecorders", []):
        if rec.get("servicePrincipal"):
            continue
        _absent_ok(
            lambda n=rec["name"]: _retry_throttled(
                lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=n)
            ),
            "NoSuchConfigurationRecorderException",
        )
    _absent_ok(
        lambda: cfg.delete_delivery_channel(DeliveryChannelName=name), "NoSuchDeliveryChannelException"
    )


def _reset_recorders(ctx):
    """Remove ANY pre-existing customer-managed configuration recorder (a singleton
    per account/region, so ambient state must be cleared for check independence)."""
    cfg = ctx.client("config")
    try:
        existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except Exception:
        return
    for rec in existing:
        name = rec.get("name")
        if name and not rec.get("servicePrincipal"):
            _delete_recorder_quiet(ctx, name)


def _reset_delivery_channels(ctx):
    """Remove ANY pre-existing delivery channel (also a singleton, limit 1)."""
    cfg = ctx.client("config")
    try:
        existing = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    except Exception:
        return
    for chan in existing:
        name = chan.get("name")
        if name:
            _delete_channel_quiet(ctx, name)


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")

    def _empty_and_delete():
        resp = s3.list_object_versions(Bucket=name)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    _absent_ok(_empty_and_delete, "NoSuchBucket")


def _ensure_bucket(ctx, name):
    """Return a real, writable S3 bucket for a Config delivery channel: create one, else reuse an
    existing bucket, else skip the check."""
    s3 = ctx.client("s3")
    try:
        kwargs = {"Bucket": name}
        if ctx.region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
        s3.create_bucket(**kwargs)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
        s3.put_bucket_tagging(
            Bucket=name,
            Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
        )
        return name
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("AccessDenied", "AccessDeniedException", "AllAccessDisabled"):
            raise

    try:
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    except Exception:
        buckets = []
    for candidate in buckets:
        if candidate.startswith("sim2real") or "config" in candidate:
            return candidate
    if buckets:
        return buckets[0]

    raise AssertionError(
        "sandbox role lacks s3:CreateBucket and no reusable S3 bucket exists; "
        "AWS Config delivery channels require a real writable S3 bucket"
    )


def _authorize_bucket_for_config(ctx, bucket, account_id):
    """Attach the bucket policy AWS Config requires in order to deliver to *bucket*."""
    s3 = ctx.client("s3")
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSConfigBucketPermissionsCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": ["s3:GetBucketAcl", "s3:ListBucket"],
                    "Resource": f"arn:aws:s3:::{bucket}",
                },
                {
                    "Sid": "AWSConfigBucketDelivery",
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/Config/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
            ],
        }
    )
    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=policy)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(
                "sandbox role cannot set an S3 bucket policy; AWS Config cannot deliver "
                "to a bucket it is not authorized to write"
            ) from exc
        raise


def _delete_config_role_quiet(ctx):
    iam = ctx.client("iam", region="us-east-1")
    _absent_ok(
        lambda: iam.detach_role_policy(RoleName=_CONFIG_ROLE_NAME, PolicyArn=_CONFIG_MANAGED_POLICY_ARN),
        "NoSuchEntity",
    )
    _absent_ok(lambda: iam.delete_role(RoleName=_CONFIG_ROLE_NAME), "NoSuchEntity")


def _ensure_config_role(ctx):
    """Return the ARN of a real IAM role config.amazonaws.com can assume (PutDeliveryChannel
    validates this); reuse it if present, skip if IAM cannot be managed."""
    # IAM is a global control plane; us-east-1 makes that explicit.
    iam = ctx.client("iam", region="us-east-1")
    try:
        try:
            return iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]["Arn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
        arn = iam.create_role(
            RoleName=_CONFIG_ROLE_NAME,
            AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )["Role"]["Arn"]
        iam.attach_role_policy(RoleName=_CONFIG_ROLE_NAME, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
        ctx.on_cleanup(lambda: _delete_config_role_quiet(ctx))
        return arn
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException", "NotAuthorized"):
            raise AssertionError(
                "sandbox role cannot manage IAM; AWS Config delivery channels require a "
                "real service role assumable by config.amazonaws.com"
            ) from exc
        raise


def _ensure_recorder(ctx, rec_name, role_arn):
    """Create this check's recorder after clearing any existing one, retrying InvalidRoleException while the
    freshly created IAM role propagates."""
    cfg = ctx.client("config")
    _reset_recorders(ctx)
    _reset_delivery_channels(ctx)
    _retry_on(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": rec_name,
                "roleARN": role_arn,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }
        ),
        codes=("InvalidRoleException",) + _THROTTLE_CODES,
    )
    ctx.on_cleanup(lambda: _delete_recorder_quiet(ctx, rec_name))


def _put_delivery_channel(ctx, chan_name, bucket):
    """PutDeliveryChannel, retrying while Config's view of the new bucket and policy lags S3."""
    cfg = ctx.client("config")
    _retry_on(
        lambda: cfg.put_delivery_channel(
            DeliveryChannel={"name": chan_name, "s3BucketName": bucket}
        ),
        codes=(
            "NoSuchBucketException",
            "InsufficientDeliveryPolicyException",
            "ThrottlingException",
        ),
    )
    ctx.on_cleanup(lambda: _delete_channel_quiet(ctx, chan_name))


def _ensure_recording_setup(ctx, rec_name, chan_name, bucket, account_id):
    """Bring Config fully online (bucket, recorder, delivery channel, recording started);
    returns the bucket used."""
    cfg = ctx.client("config")
    bucket = _ensure_bucket(ctx, bucket)
    _authorize_bucket_for_config(ctx, bucket, account_id)
    role_arn = _ensure_config_role(ctx)
    _ensure_recorder(ctx, rec_name, role_arn=role_arn)
    _put_delivery_channel(ctx, chan_name, bucket)
    _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=rec_name))
    return bucket


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder",
)
def run(ctx) -> None:
    """PutResourceConfig fails with NoRunningConfigurationRecorderException before any recorder runs, then
    rejects an unregistered CloudFormation type with ValidationException; the resource never becomes
    discoverable, and DeleteResourceConfig on that type is a no-op success."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resource_type = "MyFidelityNamespace::Testing::Widget"
    resource_id = ctx.unique_name("sim2real-behav-widget-")
    configuration = json.dumps({"Id": resource_id, "Name": "fidelity widget", "Enabled": True})
    rec_name = ctx.unique_name("sim2real-behav-cfg-rec-")
    chan_name = ctx.unique_name("sim2real-behav-cfg-chan-")
    bucket = ctx.unique_name("sim2real-behav-cfg-bucket-").replace("_", "-").lower()

    # With no running recorder, the recorder precondition is
    # reported FIRST -- before the resource type is ever validated.
    _reset_recorders(ctx)
    _reset_delivery_channels(ctx)
    pre_code, pre_code_message = _error(
        lambda: cfg.put_resource_config(
            ResourceType=resource_type,
            SchemaVersionId="1-0",
            ResourceId=resource_id,
            Configuration=configuration,
        )
    )
    assert pre_code == "NoRunningConfigurationRecorderException", f"unexpected code: {pre_code}"
    assert pre_code_message == (
        "You must create and start a configuration recorder before you call the PutResourceConfig API."
    ), pre_code_message

    _ensure_recording_setup(ctx, rec_name, chan_name, bucket, account_id)

    # Now that a recorder IS running, the unregistered custom type is rejected.
    code, code_message = _error(
        lambda: cfg.put_resource_config(
            ResourceType=resource_type,
            SchemaVersionId="1-0",
            ResourceId=resource_id,
            Configuration=configuration,
        )
    )
    assert code == "ValidationException", f"unexpected code: {code}"
    assert code_message == (
        f"Cannot find registered Resource Type with name {resource_type}. "
        "Please register the Resource Type with Cloudformation and try again."
    ), code_message

    # ... and nothing was recorded as a side effect.
    listed = cfg.list_discovered_resources(resourceType="AWS::S3::Bucket")
    assert isinstance(listed["resourceIdentifiers"], list), listed
    assert all(r["resourceId"] != resource_id for r in listed["resourceIdentifiers"]), (
        f"rejected resource must not be discoverable: {listed}"
    )

    # An unknown resource key is simply ABSENT from both lists -- Config does
    # not echo it back as "unprocessed".
    batch = cfg.batch_get_resource_config(
        resourceKeys=[{"resourceType": "AWS::S3::Bucket", "resourceId": resource_id}]
    )
    assert batch["baseConfigurationItems"] == [], batch
    assert batch["unprocessedResourceKeys"] == [], batch

    # DeleteResourceConfig does NOT validate the
    # resource type the way PutResourceConfig does -- it succeeds as a no-op even for
    # a type that Put rejects outright.
    cfg.delete_resource_config(ResourceType=resource_type, ResourceId=resource_id)

    # Terminal read, independent of the mutating delete call above: the resource
    # was never discoverable before the no-op delete, and it must still not be
    # discoverable after it.
    final = cfg.list_discovered_resources(resourceType="AWS::S3::Bucket")
    assert all(r["resourceId"] != resource_id for r in final["resourceIdentifiers"]), (
        f"resource must remain absent after the no-op delete: {final}"
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
