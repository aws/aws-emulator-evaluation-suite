"""op-delete-config-rule-nonexistent."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-delete-config-rule-nonexistent"
GROUP = "overly-permissive"
SERVICES = ["config"]

_CONFIG_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """DeleteConfigRule on a never-created name fails with NoSuchConfigRuleException rather than
    succeeding as an idempotent no-op; deleting a real ACTIVE rule first rules out a target that
    answers NoSuchConfigRuleException unconditionally."""
    _acquire_recorder_lock(ctx)
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")

    recorder_cleanup = _ensure_recorder(ctx)
    if recorder_cleanup is not None:
        ctx.on_cleanup(recorder_cleanup)

    # Positive control: a real, ACTIVE rule can be deleted successfully.
    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
        }
    )
    rule_deleted = False
    ctx.on_cleanup(
        lambda: None if rule_deleted else cfg.delete_config_rule(ConfigRuleName=rule_name)
    )

    # PutConfigRule returns before the rule is fully materialized (it starts
    # in ConfigRuleState=CREATING); wait for ACTIVE before deleting it.
    def _rule_state():
        rules = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
        return rules[0]["ConfigRuleState"] if rules else None

    state = _poll_until(_rule_state, lambda s: s == "ACTIVE", timeout_s=120, interval_s=5)
    assert state == "ACTIVE", f"expected the positive-control rule to reach ACTIVE, got {state!r}"

    cfg.delete_config_rule(ConfigRuleName=rule_name)
    rule_deleted = True

    # DeleteConfigRule is asynchronous: the rule transitions through DELETING
    # before it actually disappears, so poll rather than checking immediately.
    def _still_present():
        try:
            rules = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
        except cfg.exceptions.NoSuchConfigRuleException:
            return False
        return bool(rules)

    gone = _poll_until(
        _still_present, lambda present: present is False, timeout_s=120, interval_s=5
    )
    assert gone is False, "positive-control rule still present after a successful delete"

    # The negative: a name that was never created at all must be rejected
    # with the specific not-found code, never a lenient no-op success.
    missing = ctx.unique_name("sim2real-behav-cfg-absent-rule-")
    code, message = _error(lambda: cfg.delete_config_rule(ConfigRuleName=missing))
    assert code == "NoSuchConfigRuleException", code
    assert message == (
        f"The ConfigRule '{missing}' provided in the request is invalid. Please check the configRule name."
    ), message


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
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
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
    """Ensure a running configuration recorder (any scope suffices here since
    this check never evaluates the rule -- it only needs PutConfigRule and
    DeleteConfigRule to be allowed at all).

    Registers cleanup for anything it creates directly on ``ctx`` (so a
    partial failure mid-setup still gets torn down); returns None always.
    """
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
            cfg.put_delivery_channel(DeliveryChannel={"name": channel_name, "s3BucketName": bucket})
            last_err = None
            break
        except Exception as exc:  # IAM role trust/bucket-policy propagation lag
            last_err = exc
            time.sleep(5)
    if last_err is not None:
        raise last_err

    def _delete_channel():
        # Cleanups run last-in first-out, so this runs while the recorder is still
        # recording; AWS refuses to delete the last channel of a running recorder.
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
