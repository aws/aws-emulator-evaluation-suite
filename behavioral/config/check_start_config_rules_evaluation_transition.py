"""start-config-rules-evaluation-transition."""

from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_ROLE_ARN_CACHE = None

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

_S3_DELIVERY_BUCKET_POLICY = """{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {{"Service": "config.amazonaws.com"}},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::{bucket}"
    }},
    {{
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {{"Service": "config.amazonaws.com"}},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::{bucket}/*",
      "Condition": {{"StringEquals": {{"s3:x-amz-acl": "bucket-owner-full-control"}}}}
    }}
  ]
}}"""

def _error(fn):
    """Return (code, message) of fn()'s ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _retry_throttled(fn, attempts=8, base_delay=2.0, extra_codes=()):
    # Config's control plane has a very low burst limit and reliably trips ThrottlingException;
    # extra_codes folds in another transient error class (see _create_recorder).
    codes = ("ThrottlingException", "TooManyRequestsException") + tuple(extra_codes)
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in codes:
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _config_slr_arn(ctx):
    """The AWS Config service-linked role's ARN; the check creates it when the account lacks it."""
    iam = ctx.client("iam")
    try:
        return iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")["Role"]["Arn"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "InvalidInput" or "has been taken" not in err.get("Message", ""):
            raise
    return iam.get_role(RoleName="AWSServiceRoleForConfig")["Role"]["Arn"]


def _ensure_config_role(ctx):
    """The role ARN for ConfigurationRecorder.roleARN: the AWS Config service-linked role."""
    global _ROLE_ARN_CACHE
    if not _ROLE_ARN_CACHE:
        _ROLE_ARN_CACHE = _config_slr_arn(ctx)
    return _ROLE_ARN_CACHE


def _clear_recorders(ctx):
    cfg = ctx.client("config")
    try:
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except Exception:
        return
    for rec in recs:
        name = rec.get("name")
        try:
            _retry_throttled(lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        except Exception:
            pass
        try:
            _retry_throttled(lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        except Exception:
            pass

def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder=recorder, Tags=[{"Key": "sim2real", "Value": CHECK}]
        ),
        attempts=6,
        extra_codes=("InvalidRoleException",),
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
        )
    )
    return name

def _start_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name))
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name)
        )
    )

def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise

def _existing_delivery_bucket(ctx):
    cfg = ctx.client("config")
    try:
        channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    except Exception:
        return None
    for ch in channels:
        if ch.get("s3BucketName"):
            return ch["s3BucketName"]
    return None

def _create_delivery_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cfg-delivery-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    # CreateBucket rejects an explicit LocationConstraint naming us-east-1.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("AccessDenied", "AccessDeniedException"):
            raise
        # Cannot create buckets here; fall back to a bucket an existing delivery
        # channel already targets (its policy is known-good).
        reused = _existing_delivery_bucket(ctx)
        if not reused:
            raise AssertionError(
                "caller lacks s3:CreateBucket and no pre-existing Config delivery "
                "bucket is available for reuse"
            ) from exc
        return reused
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    try:
        s3.put_bucket_policy(
            Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket)
        )
    except Exception:
        pass
    return bucket

def _create_delivery_channel(ctx, name, bucket):
    cfg = ctx.client("config")
    channel = {"name": name, "s3BucketName": bucket}
    # The freshly-written bucket policy is eventually consistent; Config rejects a
    # delivery channel whose bucket policy has not propagated with
    # InsufficientDeliveryPolicyException.
    last = None
    for attempt in range(6):
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

CHECK = "start-config-rules-evaluation-transition"
GROUP = 'config-rule'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutEvaluations rejects a bogus ResultToken, and StartConfigRulesEvaluation on a
    never-evaluated rule flips FirstEvaluationStarted from false to true and leaves it ACTIVE
    (ConfigRuleState alone proves nothing: it is ACTIVE from creation).
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder_name)

    # A recorder that is merely PUT is not recording: StartConfigurationRecorder
    # itself refuses with NoAvailableDeliveryChannelException until a delivery
    # channel exists, and rule evaluation has no configuration-item pipeline
    # behind it (hence no observable transition) until the recorder is running.
    bucket = _create_delivery_bucket(ctx)
    channel_name = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel_name, bucket)
    _start_recorder(ctx, recorder_name)

    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda a=rule_name: cfg.delete_config_rule(ConfigRuleName=a))

    _poll_until(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0],
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        timeout_s=30,
        interval_s=2,
        description="newly created config rule reaching ACTIVE before any evaluation is requested",
    )

    # A ResultToken not tied to any active Lambda evaluation invocation must
    # be rejected -- distinct from a rule-not-found failure.
    code, message = _error(
        lambda: cfg.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType": "AWS::S3::Bucket",
                    "ComplianceResourceId": "does-not-matter",
                    "ComplianceType": "COMPLIANT",
                    "OrderingTimestamp": "2020-01-01T00:00:00Z",
                }
            ],
            ResultToken="bogus-result-token-" + rule_name,
        )
    )
    assert code == "InvalidResultTokenException", code
    assert message == "Result Token provided is invalid", message

    def _eval_status():
        return cfg.describe_config_rule_evaluation_status(ConfigRuleNames=[rule_name])[
            "ConfigRulesEvaluationStatus"
        ][0]

    baseline = _eval_status()
    assert not baseline.get("FirstEvaluationStarted", False), (
        "a config-change-triggered rule with no matching resource event and no prior "
        f"StartConfigRulesEvaluation call must not already show an evaluation, got: {baseline}"
    )

    cfg.start_config_rules_evaluation(ConfigRuleNames=[rule_name])

    started = _poll_until(
        _eval_status,
        lambda s: s.get("FirstEvaluationStarted") is True,
        timeout_s=60,
        interval_s=2,
        description=(
            "DescribeConfigRuleEvaluationStatus (an independent read, distinct from "
            "StartConfigRulesEvaluation) reporting FirstEvaluationStarted=true"
        ),
    )
    assert started.get("FirstEvaluationStarted") is True, started

    settled = _poll_until(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0],
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        timeout_s=30,
        interval_s=2,
        description="config rule state settling back to ACTIVE after the on-demand evaluation completes",
    )
    assert settled["ConfigRuleState"] == "ACTIVE", settled


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
