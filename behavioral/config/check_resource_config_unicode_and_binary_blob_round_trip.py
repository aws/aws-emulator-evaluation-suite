"""resource-config-unicode-and-binary-blob-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-config-unicode-and-binary-blob-round-trip"
GROUP = "representation"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """With a running recorder, PutResourceConfig rejects an unregistered custom resource type with
    ValidationException, and history/batch reads of the never-ingested resource fabricate nothing.
    """
    # PutResourceConfig accepts only CloudFormation-registered types, so no round trip is reachable.
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _ensure_config_recorder_running(ctx)

    # Positive control: a native type must list cleanly before the rejection below means anything.
    native = cfg.list_discovered_resources(resourceType="AWS::S3::Bucket")
    assert isinstance(native.get("resourceIdentifiers"), list), native

    ascii_resource_type = "Sim2RealTest::Widget::Resource"
    resource_id = ctx.unique_name("sim2real-resource-")

    code, message = _error_code_and_message(
        lambda: cfg.put_resource_config(
            ResourceType=ascii_resource_type,
            SchemaVersionId="1-0-0",
            ResourceId=resource_id,
            Configuration=json.dumps({"greeting": "héllo 日本語"}, ensure_ascii=False),
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"Cannot find registered Resource Type with name {ascii_resource_type}. "
        "Please register the Resource Type with Cloudformation and try again."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # GetResourceConfigHistory over a resource that was never ingested reports
    # not-found precisely, rather than fabricating an empty-but-successful
    # configuration item list.
    code2, message2 = _error_code_and_message(
        lambda: cfg.get_resource_config_history(
            resourceType="AWS::S3::Bucket", resourceId=resource_id
        )
    )
    assert code2 == "ResourceNotDiscoveredException", (
        f"expected ResourceNotDiscoveredException, got {code2!r}"
    )
    expected_message2 = (
        f"Resource {resource_id} of resourceType:AWS::S3::Bucket is unknown or has not been discovered"
    )
    assert message2 == expected_message2, f"expected {expected_message2!r}, got {message2!r}"

    # BatchGetResourceConfig over the same never-ingested resource key does not
    # fabricate a configuration item for it (it comes back either omitted
    # entirely or explicitly listed as unprocessed -- never fabricated data).
    resp = cfg.batch_get_resource_config(
        resourceKeys=[{"resourceType": "AWS::S3::Bucket", "resourceId": resource_id}]
    )
    assert resp.get("baseConfigurationItems", []) == [], (
        f"expected no fabricated configuration item for a never-ingested resource, got {resp!r}"
    )




def _error_code_and_message(fn):
    """Return (code, message) of fn()'s ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _ensure_config_recorder_running(ctx) -> None:
    """Ensure a customer-managed recorder is recording, as PutResourceConfig requires
    (NoRunningConfigurationRecorderException otherwise); provisions one with cleanup if needed."""
    cfg = ctx.client("config")
    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        name = existing[0]["name"]
        status = cfg.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[name]
        )["ConfigurationRecordersStatus"][0]
        if status.get("recording"):
            return
        channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
        if channels:
            def _try_start_existing() -> bool:
                try:
                    cfg.start_configuration_recorder(ConfigurationRecorderName=name)
                    return True
                except ClientError as exc:
                    if exc.response["Error"]["Code"] == "NoAvailableDeliveryChannelException":
                        return False
                    raise

            _poll_until(_try_start_existing, lambda ok: ok, timeout_s=60.0, interval_s=3.0)
            ctx.on_cleanup(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
            return

        # A stopped recorder without a delivery channel can never be started, so it is
        # replaced by a complete recorder, role, bucket and channel below.
        cfg.delete_configuration_recorder(ConfigurationRecorderName=name)

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-cfgrole-")
    bucket_name = ctx.unique_name("sim2real-cfgbucket-").lower()

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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    config_policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=config_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=config_policy_arn)
    )

    s3_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                    "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                    "Condition": {"StringLike": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetBucketAcl"],
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                },
            ],
        }
    )
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-config-s3-access", PolicyDocument=s3_policy
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-config-s3-access")
    )

    # CreateBucket rejects an explicit LocationConstraint of us-east-1.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))

    def _try_put_recorder() -> bool:
        try:
            cfg.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": role_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidRoleException":
                return False
            raise

    _poll_until(_try_put_recorder, lambda ok: ok, timeout_s=60.0, interval_s=3.0)
    ctx.on_cleanup(lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=role_name))

    def _try_put_channel() -> bool:
        try:
            cfg.put_delivery_channel(
                DeliveryChannel={"name": role_name, "s3BucketName": bucket_name}
            )
            return True
        except ClientError as exc:
            # The role's inline S3 policy is subject to IAM's eventual
            # consistency; Config validates delivery permissions synchronously,
            # so retry until the policy has propagated.
            if exc.response["Error"]["Code"] == "InsufficientDeliveryPolicyException":
                return False
            raise

    # An account holds at most one delivery channel; when one is already present
    # without a recorder, the new recorder starts against it and it is left in place.
    if not cfg.describe_delivery_channels().get("DeliveryChannels", []):
        _poll_until(_try_put_channel, lambda ok: ok, timeout_s=90.0, interval_s=5.0)
        ctx.on_cleanup(lambda: cfg.delete_delivery_channel(DeliveryChannelName=role_name))

    def _try_start() -> bool:
        try:
            cfg.start_configuration_recorder(ConfigurationRecorderName=role_name)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoAvailableDeliveryChannelException":
                return False
            raise

    _poll_until(_try_start, lambda ok: ok, timeout_s=60.0, interval_s=3.0)
    ctx.on_cleanup(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=role_name))


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


