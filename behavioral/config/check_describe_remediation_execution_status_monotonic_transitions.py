"""describe-remediation-execution-status-monotonic-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-remediation-execution-status-monotonic-transitions"
GROUP = "state-machine"
SERVICES = ["config"]

_CONFIG_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_STATE_RANK = {"QUEUED": 0, "PENDING": 0, "IN_PROGRESS": 1, "SUCCEEDED": 2, "FAILED": 2, "UNKNOWN": 2}


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


def _create_no_permissions_automation_role(ctx) -> str:
    """An IAM role SSM can assume but that carries no permissions at all, so any
    SSM Automation step that touches another AWS API fails deterministically."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ssmrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """Polling a remediation execution's status through DescribeRemediationExecutionStatus
    shows a state progression that only ever moves forward (QUEUED -> IN_PROGRESS ->
    a terminal state) and never regresses to an earlier state."""
    _acquire_recorder_lock(ctx)
    _restore_config_recorder_on_teardown(ctx)
    _ensure_recorder_recording(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-remediation-target-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    rule_name = ctx.unique_name("sim2real-versioning-rule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"},
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
        }
    )
    ctx.on_cleanup(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))

    automation_role_arn = _create_no_permissions_automation_role(ctx)

    cfg.put_remediation_configurations(
        RemediationConfigurations=[
            {
                "ConfigRuleName": rule_name,
                "TargetType": "SSM_DOCUMENT",
                "TargetId": "AWS-ConfigureS3BucketVersioning",
                "Parameters": {
                    "BucketName": {"StaticValue": {"Values": [bucket]}},
                    "AutomationAssumeRole": {"StaticValue": {"Values": [automation_role_arn]}},
                },
            }
        ]
    )
    ctx.on_cleanup(lambda: cfg.delete_remediation_configuration(ConfigRuleName=rule_name))

    resource_key = {"resourceType": "AWS::S3::Bucket", "resourceId": bucket}
    start_resp = cfg.start_remediation_execution(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
    # StartRemediationExecution can report the resource as a FailedItem (e.g.
    # "resource compliance unknown") if the rule hasn't evaluated it yet.
    # StartConfigRulesEvaluation is itself rate-limited, so trigger it at most
    # once and then just wait/retry the remediation call.
    if start_resp.get("FailedItems"):
        try:
            cfg.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
        except ClientError:
            pass
        # a rule on a recorder this check just started can take minutes to evaluate the bucket
        deadline = time.monotonic() + 420.0
        while start_resp.get("FailedItems") and time.monotonic() < deadline:
            time.sleep(2.0)
            start_resp = cfg.start_remediation_execution(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
    assert not start_resp.get("FailedItems"), (
        f"StartRemediationExecution never accepted the resource: {start_resp}"
    )

    def _current_state():
        statuses = cfg.describe_remediation_execution_status(
            ConfigRuleName=rule_name, ResourceKeys=[resource_key]
        )["RemediationExecutionStatuses"]
        return statuses[0]["State"] if statuses else None

    observed: list[str] = []
    deadline = time.monotonic() + 180.0
    terminal = {"SUCCEEDED", "FAILED", "UNKNOWN"}
    while time.monotonic() < deadline:
        state = _current_state()
        if state is not None and (not observed or observed[-1] != state):
            observed.append(state)
        if state in terminal:
            break
        time.sleep(2.0)

    assert observed, "never observed any remediation execution state"
    assert observed[-1] in terminal, f"remediation execution never reached a terminal state: {observed}"

    ranks = [_STATE_RANK[s] for s in observed]
    assert ranks == sorted(ranks), (
        f"remediation execution state regressed to an earlier stage: {observed} (ranks {ranks})"
    )
    # With an automation-assume-role that carries no permissions, the SSM
    # automation deterministically fails at its first privileged step.
    assert observed[-1] == "FAILED", f"expected the execution to end FAILED, ended {observed[-1]!r}"


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
