"""deploy-conformance-pack-duplicate-create-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-conformance-pack-duplicate-create-rejected"
GROUP = "deploy"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A second PutConformancePack with a different template while the pack is CREATE_IN_PROGRESS fails
    with ResourceInUseException and has no effect; the original completes, and the same update
    succeeds once the pack is idle, so the rejection is a state-conflict guard."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    _ensure_active_recorder(ctx)
    pack_name = ctx.unique_name("sim2real-cpackdup-")

    rule_a = ctx.unique_name("sim2real-cpackdup-rulea-")
    rule_b = ctx.unique_name("sim2real-cpackdup-ruleb-")
    # Conformance pack TemplateBody only supports YAML for the two allowed
    # resource types (AWS::Config::ConfigRule / RemediationConfiguration) --
    # a JSON document is rejected with ConformancePackTemplateValidationException.
    template_a = f"""
Resources:
  RuleA:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: {rule_a}
      Source:
        Owner: AWS
        SourceIdentifier: IAM_ROOT_ACCESS_KEY_CHECK
"""
    template_b = f"""
Resources:
  RuleB:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: {rule_b}
      Source:
        Owner: AWS
        SourceIdentifier: IAM_PASSWORD_POLICY
"""

    config.put_conformance_pack(ConformancePackName=pack_name, TemplateBody=template_a)
    ctx.on_cleanup(lambda: _delete_pack_when_idle(config, pack_name))

    # Fired immediately, while the first request is (almost certainly) still
    # CREATE_IN_PROGRESS -- a second Put for the SAME pack name with a DIFFERENT
    # template must be rejected, not silently queued or applied.
    code, message = _error(
        lambda: config.put_conformance_pack(ConformancePackName=pack_name, TemplateBody=template_b)
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    assert message == (
        f"A workflow is currently in progress for the Conformance Pack: {pack_name}. "
        "Please try later."
    ), message

    # Positive control: the original request must still reach CREATE_COMPLETE.
    detail = _poll_until(
        lambda: config.describe_conformance_pack_status(ConformancePackNames=[pack_name])[
            "ConformancePackStatusDetails"
        ][0],
        lambda d: d["ConformancePackState"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=10,
    )
    assert detail["ConformancePackState"] == "CREATE_COMPLETE", (
        f"reason={detail.get('ConformancePackStatusReason')} detail={detail}"
    )

    # The rejected second template must have had no effect: only RuleA exists.
    # AWS Config appends a "-conformance-pack-<random>" suffix to a rule deployed through a
    # pack, so match by prefix rather than the bare TemplateBody name.
    rule_a_present = _poll_until(
        lambda: _all_config_rule_names(config),
        lambda names: any(n.startswith(rule_a) for n in names),
        timeout_s=60,
        interval_s=5,
    )
    assert any(n.startswith(rule_a) for n in rule_a_present), "the original (accepted) rule should exist"
    assert not any(n.startswith(rule_b) for n in rule_a_present), (
        "the rejected duplicate-create template must not have been applied"
    )

    # Once the pack is out of CREATE_IN_PROGRESS the identical call must succeed, so the
    # rejection was bound to the state-conflict window. A pack update never reports an UPDATE_*
    # state (ConformancePackState stays CREATE_COMPLETE), so LastUpdateCompletedTime advancing
    # is the signal that the update ran.
    prior_update_ts = detail.get("LastUpdateCompletedTime")
    config.put_conformance_pack(ConformancePackName=pack_name, TemplateBody=template_b)
    updated = _poll_until(
        lambda: config.describe_conformance_pack_status(ConformancePackNames=[pack_name])[
            "ConformancePackStatusDetails"
        ][0],
        lambda d: d.get("LastUpdateCompletedTime") != prior_update_ts
        and d["ConformancePackState"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=10,
    )
    assert updated["ConformancePackState"] == "CREATE_COMPLETE", (
        f"reason={updated.get('ConformancePackStatusReason')} detail={updated}"
    )
    rule_b_present = _poll_until(
        lambda: _all_config_rule_names(config),
        lambda names: any(n.startswith(rule_b) for n in names),
        timeout_s=60,
        interval_s=5,
    )
    assert any(n.startswith(rule_b) for n in rule_b_present), (
        "after the conflict clears, the identical call must now take effect"
    )



def _all_config_rule_names(config):
    names = set()
    paginator = config.get_paginator("describe_config_rules")
    for page in paginator.paginate():
        names.update(r["ConfigRuleName"] for r in page["ConfigRules"])
    return names

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _put_recorder_with_retry(config, name, role_arn, *, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_pack_when_idle(config, pack_name, *, timeout_s=240.0, interval_s=10.0):
    """DeleteConformancePack is refused while a pack workflow runs; retry within a deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            config.delete_conformance_pack(ConformancePackName=pack_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchConformancePackException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _put_delivery_channel_with_retry(config, name, bucket, *, timeout_s=90.0, interval_s=5.0):
    """Config assumes the just-created role to validate delivery; until IAM propagates it
    answers InsufficientDeliveryPolicyException, so retry that one code within a deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            config.put_delivery_channel(DeliveryChannel={"name": name, "s3BucketName": bucket})
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "InsufficientDeliveryPolicyException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _ensure_active_recorder(ctx):
    """Return (recorder_name, created) for an active recorder + delivery channel, provisioning one if
    needed: a pack's ConfigRule cannot be created without an active recorder
    (NoAvailableConfigurationRecorderException)."""
    config = ctx.client("config")

    existing = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if existing:
        name = existing[0]["name"]
        status = config.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[name]
        )["ConfigurationRecordersStatus"][0]
        if status.get("recording"):
            return name, False
        channels = config.describe_delivery_channels().get("DeliveryChannels", [])
        if channels:
            config.start_configuration_recorder(ConfigurationRecorderName=name)
            return name, False

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    # The delivery channel is its own account-global singleton, independent of the
    # recorder -- a channel can survive a recorder that was deleted (or never created)
    # by a different check sharing this account. Adopt it rather than calling
    # PutDeliveryChannel blind, which fails with MaxNumberOfDeliveryChannelsExceededException
    # when one already exists.
    adopt_channel = config.describe_delivery_channels().get("DeliveryChannels", [])

    name = ctx.unique_name("sim2real-cfghelper-rec-")
    bucket = None
    if not adopt_channel:
        bucket = ctx.unique_name("sim2real-cfghelper-bkt-").lower()
        region = ctx.region
        if region == "us-east-1":  # S3 CreateBucket rejects LocationConstraint for this region specifically
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

        def _empty_and_delete_bucket():
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        ctx.on_cleanup(_empty_and_delete_bucket)

    role_name = ctx.unique_name("sim2real-cfghelper-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
        )
    )
    if bucket is not None:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="ConfigS3Delivery",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:GetBucketAcl", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }],
            }),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="ConfigS3Delivery"))
        account_id = sts.get_caller_identity()["Account"]
        bucket_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket}",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/Config/*",
                },
            ],
        })
        s3.put_bucket_policy(Bucket=bucket, Policy=bucket_policy)

    # IAM propagation before wiring Config to the new role: Config validates the role
    # by assuming it, and a just-created role/policy is not always visible yet, so
    # retry on the specific InvalidRoleException instead of guessing a fixed wait.
    _put_recorder_with_retry(config, name, role_arn)
    ctx.on_cleanup(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=name))
    if not adopt_channel:
        _put_delivery_channel_with_retry(config, name, bucket)
        ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=name))
    config.start_configuration_recorder(ConfigurationRecorderName=name)
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=name))
    return name, True


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
