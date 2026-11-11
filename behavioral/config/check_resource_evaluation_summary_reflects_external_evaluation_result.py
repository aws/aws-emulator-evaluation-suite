"""resource-evaluation-summary-reflects-external-evaluation-result."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-evaluation-summary-reflects-external-evaluation-result"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A compliance result submitted via PutExternalEvaluation for a process-check rule (deployed
    through a conformance pack) is visible, with the same ComplianceType and resource identity,
    through GetComplianceDetailsByResource."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _ensure_recorder_and_channel(ctx)

    # AWS_CONFIG_PROCESS_CHECK rules cannot be created via a bare PutConfigRule call --
    # real AWS rejects that with InvalidParameterValueException ("is invalid ... when AWS
    # is the Owner"). They can only be deployed as part of a
    # conformance pack, which may suffix the requested name, so the actual rule name is
    # resolved afterward rather than assumed.
    rule_prefix = ctx.unique_name("sim2real-process-check-")
    pack_name = ctx.unique_name("sim2real-pc-pack-")
    template_body = f"""Resources:
  Sim2RealProcessCheck:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: {rule_prefix}
      Description: sim2real behavioral process-check rule
      Source:
        Owner: AWS
        SourceIdentifier: AWS_CONFIG_PROCESS_CHECK
"""
    config.put_conformance_pack(
        ConformancePackName=pack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_conformance_pack(config, pack_name))

    _poll_until(
        lambda: _conformance_pack_state(config, pack_name),
        lambda state: state == "CREATE_COMPLETE",
        timeout_s=180,
        interval_s=5,
    )
    rule_name = _poll_until(
        lambda: _active_rule_by_prefix(config, rule_prefix),
        lambda name: name is not None,
        timeout_s=60,
        interval_s=3,
    )

    config.put_external_evaluation(
        ConfigRuleName=rule_name,
        ExternalEvaluation={
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": account_id,
            "ComplianceType": "NON_COMPLIANT",
            "Annotation": "sim2real-behavioral-check",
            "OrderingTimestamp": datetime.now(timezone.utc),
        },
    )

    def _details():
        return config.get_compliance_details_by_resource(ResourceType="AWS::::Account", ResourceId=account_id)["EvaluationResults"]

    results = _poll_until(
        _details,
        lambda rs: any(r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ConfigRuleName"] == rule_name for r in rs),
        timeout_s=60,
        interval_s=3,
    )
    match = next(r for r in results if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ConfigRuleName"] == rule_name)
    assert match["ComplianceType"] == "NON_COMPLIANT", (
        f"expected ComplianceType NON_COMPLIANT (as submitted via PutExternalEvaluation), "
        f"got {match['ComplianceType']!r}"
    )
    assert match["Annotation"] == "sim2real-behavioral-check", (
        f"expected Annotation to round-trip verbatim as 'sim2real-behavioral-check', "
        f"got {match['Annotation']!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _conformance_pack_state(config, pack_name):
    statuses = config.describe_conformance_pack_status(ConformancePackNames=[pack_name])["ConformancePackStatusDetails"]
    if not statuses:
        return None
    state = statuses[0]["ConformancePackState"]
    if state == "CREATE_FAILED":
        raise AssertionError(f"conformance pack {pack_name} failed to deploy: {statuses[0].get('ConformancePackStatusReason', '')}")
    return state


def _active_rule_by_prefix(config, rule_name_prefix):
    paginator = config.get_paginator("describe_config_rules")
    for page in paginator.paginate():
        for rule in page.get("ConfigRules", []):
            if rule["ConfigRuleName"].startswith(rule_name_prefix) and rule["ConfigRuleState"] == "ACTIVE":
                return rule["ConfigRuleName"]
    return None


def _delete_conformance_pack(config, pack_name):
    deadline = time.monotonic() + 60.0
    while True:
        try:
            config.delete_conformance_pack(ConformancePackName=pack_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchConformancePackException":
                return
            if code != "ResourceInUseException" or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket_name)


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    """Call fn, retrying Config throttling with exponential backoff; other errors re-raise."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") not in ("ThrottlingException", "TooManyRequestsException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


_RECORDER_FIELDS = ("name", "roleARN", "recordingGroup", "recordingMode")


def _clear_recorders_and_channels(ctx):
    """Delete every customer-managed recorder and every delivery channel.

    One cleanup restores them all: recorders, then channels, then recording on the
    recorders that were recording. Returns (recorder names, channel names) deleted.
    """
    cfg = ctx.client("config")
    recording = {
        st["name"]: st.get("recording", False)
        for st in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    }
    recorders = [
        {k: r[k] for k in _RECORDER_FIELDS if k in r}
        for r in cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not r.get("servicePrincipal")
    ]
    channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    was_recording = [r["name"] for r in recorders if recording.get(r["name"], False)]

    for name in was_recording:
        _retry_throttled(lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
    for ch in channels:
        _retry_throttled(lambda n=ch["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
    for rec in recorders:
        _retry_throttled(lambda n=rec["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))

    def _restore():
        for rec in recorders:
            _retry_throttled(lambda r=rec: cfg.put_configuration_recorder(ConfigurationRecorder=r))
        # A channel can outlive its recorder, but it cannot be put back without one.
        for ch in channels if recorders else ():
            _retry_throttled(lambda c=ch: cfg.put_delivery_channel(DeliveryChannel=c))
        for name in was_recording:
            _retry_throttled(lambda n=name: cfg.start_configuration_recorder(ConfigurationRecorderName=n))

    ctx.on_cleanup(_restore)
    return [r["name"] for r in recorders], [c["name"] for c in channels]


def _ensure_recorder_and_channel(ctx):
    config = ctx.client("config")
    _clear_recorders_and_channels(ctx)

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-cfg-recorder-role-")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"))

    bucket_name = ctx.unique_name("sim2real-cfg-bucket-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real:behavioral-check", "Value": CHECK}]},
    )
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AWSConfigBucketPermissionsCheck", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket_name}"},
            {"Sid": "AWSConfigBucketExistenceCheck", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket_name}"},
            {"Sid": "AWSConfigBucketDelivery", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*", "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    recorder_name = ctx.unique_name("sim2real-cfg-recorder-")
    deadline = time.monotonic() + 90
    while True:
        try:
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    # AWS::IAM::Role is itself a global resource type; naming it explicitly in
                    # resourceTypes while also setting includeGlobalResourceTypes=True is now
                    # rejected by real AWS as InvalidRecordingGroupException.
                    "recordingGroup": {"allSupported": False, "includeGlobalResourceTypes": False, "resourceTypes": ["AWS::IAM::Role"]},
                },
                Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name))

    # The role's trust relationship and the bucket policy that names it can both still be
    # propagating even after put_configuration_recorder above accepted the role, so retry the
    # delivery channel's own assume-role probe on InsufficientDeliveryPolicyException (measured
    # on real AWS) rather than treating a slow-but-correct role as a hard failure.
    delivery_deadline = time.monotonic() + 60
    while True:
        try:
            config.put_delivery_channel(DeliveryChannel={"name": recorder_name, "s3BucketName": bucket_name})
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InsufficientDeliveryPolicyException" and time.monotonic() < delivery_deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=recorder_name))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name))
    return recorder_name


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
