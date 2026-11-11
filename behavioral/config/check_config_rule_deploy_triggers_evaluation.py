"""config-rule-deploy-triggers-evaluation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "config-rule-deploy-triggers-evaluation"
GROUP = "deploy"
SERVICES = ["config"]

_CONFIG_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A deployed ConfigRule evaluates its scoped bucket to a real compliance result; a versioned
    control bucket under a second rule proves the rule reads the bucket's attribute rather than
    answering NON_COMPLIANT unconditionally."""
    _acquire_recorder_lock(ctx)
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")

    recorder_cleanup = _ensure_recorder(ctx)
    if recorder_cleanup is not None:
        ctx.on_cleanup(recorder_cleanup)

    tags_kv = [{"Key": "sim2real-check", "Value": "config-rule-deploy-triggers-evaluation"}]

    bucket_name = _create_bucket(ctx, s3, "sim2real-cfg-noversion-", tags_kv)
    versioned_bucket_name = _create_bucket(ctx, s3, "sim2real-cfg-versioned-", tags_kv)
    s3.put_bucket_versioning(
        Bucket=versioned_bucket_name, VersioningConfiguration={"Status": "Enabled"}
    )

    rule_name = _put_versioning_rule(ctx, cfg, "sim2real-s3-versioning-", bucket_name, tags_kv)
    versioned_rule_name = _put_versioning_rule(
        ctx, cfg, "sim2real-s3-versioning-ctrl-", versioned_bucket_name, tags_kv
    )

    # Wait for the recorder to discover both buckets before evaluating -- a rule
    # evaluates against configuration items that already exist in inventory.
    _poll_until(
        lambda: cfg.list_discovered_resources(
            resourceType="AWS::S3::Bucket",
            resourceIds=[bucket_name, versioned_bucket_name],
        )["resourceIdentifiers"],
        lambda ids: len(ids) == 2,
        timeout_s=600,
        interval_s=15,
    )

    def _trigger_and_get_compliance():
        result = cfg.describe_compliance_by_config_rule(
            ConfigRuleNames=[rule_name, versioned_rule_name]
        )
        by_name = {
            r["ConfigRuleName"]: r["Compliance"]["ComplianceType"]
            for r in result["ComplianceByConfigRules"]
        }
        if rule_name not in by_name or versioned_rule_name not in by_name:
            return None
        return by_name[rule_name], by_name[versioned_rule_name]

    _trigger_evaluation(cfg, rule_name)
    _trigger_evaluation(cfg, versioned_rule_name)
    compliance, versioned_compliance = _poll_until(
        _trigger_and_get_compliance,
        lambda c: c is not None and all(v in ("COMPLIANT", "NON_COMPLIANT") for v in c),
        timeout_s=600,
        interval_s=20,
    )
    assert compliance == "NON_COMPLIANT", (
        f"expected the versionless bucket to be flagged NON_COMPLIANT, got {compliance!r}"
    )
    assert versioned_compliance == "COMPLIANT", (
        "expected the positive control (versioning already enabled) to be flagged "
        f"COMPLIANT, got {versioned_compliance!r} -- a rule that answers NON_COMPLIANT "
        "unconditionally must not pass this check"
    )


# ===== helpers =====
def _create_bucket(ctx, s3, prefix: str, tags_kv: list) -> str:
    bucket_name = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": tags_kv})
    return bucket_name


def _put_versioning_rule(ctx, cfg, prefix: str, bucket_name: str, tags_kv: list) -> str:
    rule_name = ctx.unique_name(prefix)
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Scope": {
                "ComplianceResourceTypes": ["AWS::S3::Bucket"],
                "ComplianceResourceId": bucket_name,
            },
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
        },
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))
    return rule_name


def _trigger_evaluation(cfg, rule_name: str) -> None:
    """Kick off an on-demand rule evaluation exactly once, backing off on the
    account's StartConfigRulesEvaluation rate limit instead of hammering it
    (managed rules also re-evaluate on their own periodic/CI-triggered
    schedule, so a ResourceInUseException just means one is already running
    and is not itself an error)."""
    last_err = None
    for attempt in range(6):
        try:
            cfg.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
            return
        except cfg.exceptions.ResourceInUseException:
            return
        except cfg.exceptions.LimitExceededException as exc:
            last_err = exc
            time.sleep(20 * (attempt + 1))
    if last_err is not None:
        raise last_err


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
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
