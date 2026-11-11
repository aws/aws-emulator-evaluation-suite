"""put-resource-config-rejects-unregistered-type."""

from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return (code, message) from its ClientError. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on.
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


def _grant_describe_type(ctx, role_arn):
    """Grant cloudformation:DescribeType on the recorder's role: without it PutResourceConfig fails
    with InsufficientPermissionsException for ANY type, hiding the rejection under test. Additive only."""
    role_name = role_arn.rsplit("/", 1)[-1]
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-cfg-cfn-describe-type",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["cloudformation:DescribeType", "cloudformation:ListTypes"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )


def _ensure_recorder_running(ctx):
    """Adopt or create a running recorder: without one PutResourceConfig fails with
    NoRunningConfigurationRecorderException before ResourceType is validated. Cleans up only what
    it created."""
    cfg = ctx.client("config")
    existing = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        recorder_name = existing[0]["name"]
        _grant_describe_type(ctx, existing[0]["roleARN"])
    else:
        iam = ctx.client("iam")
        s3 = ctx.client("s3")
        account_id = ctx.client("sts").get_caller_identity()["Account"]

        role_name = ctx.unique_name("sim2real-behav-cfg-role-")
        bucket_name = ctx.unique_name("sim2real-behav-cfg-bucket-").replace("_", "-").lower()
        recorder_name = ctx.unique_name("sim2real-behav-cfg-rec-")
        channel_name = ctx.unique_name("sim2real-behav-cfg-chan-")

        trust_policy = json.dumps(
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
        role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
            "Role"
        ]["Arn"]

        def _delete_role():
            # DeleteRole does not cascade: IAM refuses it with DeleteConflict
            # while any inline policy remains attached.
            for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            iam.delete_role(RoleName=role_name)

        ctx.on_cleanup(_delete_role)

        # us-east-1 is region-pinned by S3's own API contract: CreateBucket rejects an
        # explicit LocationConstraint there, so this is not a check-chosen region.
        create_bucket_kwargs = {"Bucket": bucket_name}
        if ctx.region != "us-east-1":
            create_bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
        s3.create_bucket(**create_bucket_kwargs)

        def _delete_bucket():
            objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket_name)

        ctx.on_cleanup(_delete_bucket)

        # New buckets default to ACLs-disabled, which makes Config's
        # bucket-owner-full-control delivery check fail; re-enable ACLs.
        s3.put_bucket_ownership_controls(
            Bucket=bucket_name,
            OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]},
        )
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
            PolicyName="sim2real-behav-cfg-s3-delivery",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:PutObject", "s3:GetBucketAcl", "s3:ListBucket"],
                            "Resource": [
                                f"arn:aws:s3:::{bucket_name}",
                                f"arn:aws:s3:::{bucket_name}/*",
                            ],
                        }
                    ],
                }
            ),
        )
        _grant_describe_type(ctx, role_arn)

        # IAM role trust/permissions propagation is eventually consistent.
        deadline = time.monotonic() + 30.0
        last_error = None
        while time.monotonic() < deadline:
            try:
                cfg.put_configuration_recorder(
                    ConfigurationRecorder={"name": recorder_name, "roleARN": role_arn}
                )
                last_error = None
                break
            except ClientError as exc:
                last_error = exc
                time.sleep(2.0)
        if last_error is not None:
            raise last_error
        ctx.on_cleanup(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )

        if not cfg.describe_delivery_channels().get("DeliveryChannels", []):
            deadline = time.monotonic() + 30.0
            last_error = None
            while time.monotonic() < deadline:
                try:
                    cfg.put_delivery_channel(
                        DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}
                    )
                    last_error = None
                    break
                except ClientError as exc:
                    last_error = exc
                    time.sleep(3.0)
            if last_error is not None:
                raise last_error

            def _delete_channel():
                # Cleanups run last-in first-out, so this runs while the recorder is
                # still recording; AWS refuses to delete the last channel of a running
                # recorder.
                cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder_name)
                cfg.delete_delivery_channel(DeliveryChannelName=channel_name)

            ctx.on_cleanup(_delete_channel)

    status = cfg.describe_configuration_recorder_status(ConfigurationRecorderNames=[recorder_name])[
        "ConfigurationRecordersStatus"
    ][0]
    if not status.get("recording", False):
        _retry_throttled(
            lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        status = cfg.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[recorder_name]
        )["ConfigurationRecordersStatus"][0]
        if status.get("recording", False):
            return
        time.sleep(1.0)
    raise AssertionError("configuration recorder never reached the 'recording' state")


CHECK = "put-resource-config-rejects-unregistered-type"
GROUP = "resource-config"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """With a recorder running, PutResourceConfig rejects a custom type that has no CloudFormation
    registry registration with ValidationException naming the type, and nothing is recorded."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _ensure_recorder_running(ctx)

    # A recorder in the "recording" state is not on its own proof that Config's
    # data plane is healthy for THIS account; an independent, known-native type
    # must list cleanly (even if empty) before the rejection below means anything.
    native = cfg.list_discovered_resources(resourceType="AWS::S3::Bucket")
    assert isinstance(native["resourceIdentifiers"], list), native

    resource_id = ctx.unique_name("sim2real-behav-cfg-custom-res-")
    resource_type = "Sim2Real::FidelityProbe::Widget"

    def _put():
        return cfg.put_resource_config(
            ResourceType=resource_type,
            SchemaVersionId="1-0",
            ResourceId=resource_id,
            Configuration=json.dumps({"note": "should not be written"}),
        )

    # The DescribeType grant above is a fresh IAM policy; it can take a few
    # seconds to propagate, during which Config still reports the pre-grant
    # InsufficientPermissionsException rather than the type-registration
    # rejection this check targets. Retry that specific code only.
    deadline = time.monotonic() + 30.0
    code, message = _error(_put)
    while code == "InsufficientPermissionsException" and time.monotonic() < deadline:
        time.sleep(3.0)
        code, message = _error(_put)
    assert code == "ValidationException", code
    assert message == (
        f"Cannot find registered Resource Type with name {resource_type}. "
        "Please register the Resource Type with Cloudformation and try again."
    ), message

    # Nothing may have been recorded as a side effect of the failed write.
    discovered = cfg.list_discovered_resources(
        resourceType=resource_type, resourceIds=[resource_id]
    )["resourceIdentifiers"]
    assert discovered == [], discovered

    batch = cfg.batch_get_resource_config(
        resourceKeys=[{"resourceType": resource_type, "resourceId": resource_id}]
    )
    assert batch["baseConfigurationItems"] == [], batch
    assert batch["unprocessedResourceKeys"] == [], batch


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
