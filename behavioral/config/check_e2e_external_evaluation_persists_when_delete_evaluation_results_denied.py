"""e2e-external-evaluation-persists-when-delete-evaluation-results-denied."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-external-evaluation-persists-when-delete-evaluation-results-denied"
GROUP = "e2e"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutExternalEvaluation on a conformance-pack process-check rule is visible via
    GetComplianceDetailsByConfigRule; DeleteEvaluationResults on that service-linked rule fails with
    AccessDeniedException and the injected result stays in place."""
    _restore_config_recorder_on_teardown(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    config = ctx.client("config")

    _ensure_configuration_recorder(ctx)

    rule_prefix = ctx.unique_name("sim2real-process-check-")
    actual_rule_name = _deploy_process_check_pack(ctx, config, rule_prefix)

    resource_id = account_id
    ordering_time = datetime.datetime.now(datetime.timezone.utc)

    config.put_external_evaluation(
        ConfigRuleName=actual_rule_name,
        ExternalEvaluation={
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": resource_id,
            "ComplianceType": "NON_COMPLIANT",
            "Annotation": "sim2real manual review failed",
            "OrderingTimestamp": ordering_time,
        },
    )

    injected = _poll_for_resource(config, actual_rule_name, resource_id, timeout_s=60)
    assert injected["ComplianceType"] == "NON_COMPLIANT"
    assert injected["Annotation"] == "sim2real manual review failed"

    # DeleteEvaluationResults is rejected for a process-check rule
    # deployed through a conformance pack: such rules are owned by the
    # conformance-pack service (a "ServiceLinkedConfigRule"), so only that
    # service -- not the caller -- may clear their evaluation results directly.
    delete_code, delete_message = _error(lambda: config.delete_evaluation_results(ConfigRuleName=actual_rule_name))
    assert delete_code == "AccessDeniedException", delete_code
    # The owner AWS names between these fixed parts is an AWS-side identifier the check never holds.
    assert delete_message.startswith("An AWS service owns ") and delete_message.endswith(
        ". You do not have permissions to take action on this rule."
    ), delete_message

    # The injected result is therefore still present -- DeleteEvaluationResults
    # really was rejected, not silently a no-op success.
    still_present = _find_result_for_resource(config, actual_rule_name, resource_id)
    assert still_present is not None
    assert still_present["ComplianceType"] == "NON_COMPLIANT"


def _safe(fn, *gone_codes, busy=()) -> None:
    """Run a teardown call: return on the resource's not-found codes, retry every 2 s the codes AWS
    answers while a dependency is still being released, and raise anything else."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _empty_and_delete_bucket(s3, bucket) -> None:
    """Config writes into its delivery bucket, so remove the objects before the bucket."""
    for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _error(fn):
    """Call fn(); return (error code, message), raising if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _retry(fn, attempts: int = 8, delay: float = 5.0, retry_codes: set[str] | None = None):
    from botocore.exceptions import ClientError

    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if retry_codes is None or code in retry_codes:
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _ensure_configuration_recorder(ctx) -> None:
    """Reuse an existing configuration recorder, or create a minimal one if none
    exists yet -- PutConfigRule requires at least one to exist in the account."""
    config = ctx.client("config")
    if config.describe_configuration_recorders().get("ConfigurationRecorders", []):
        return

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-config-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"), "NoSuchEntity")
    )

    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-config-bucket-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _safe(lambda: _empty_and_delete_bucket(s3, bucket_name), "NoSuchBucket", busy=("BucketNotEmpty",)))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_policy = {
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
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}]},
    )

    recorder_name = ctx.unique_name("sim2real-recorder-")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": recorder_name,
            "roleARN": role_arn,
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
        },
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name), "NoSuchConfigurationRecorderException"))

    channel_name = ctx.unique_name("sim2real-channel-")
    _retry(
        lambda: config.put_delivery_channel(DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}),
        retry_codes={"InsufficientDeliveryPolicyException"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name), "NoSuchDeliveryChannelException"))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: _safe(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name), "NoSuchConfigurationRecorderException"))


def _deploy_process_check_pack(ctx, config, rule_prefix: str, attempts: int = 2) -> str:
    """Deploy a process-check ConfigRule via a conformance pack (PutConfigRule rejects
    AWS_CONFIG_PROCESS_CHECK); retries once with fresh names if creation transiently fails."""
    last_failure = None
    for attempt in range(attempts):
        rule_name = rule_prefix if attempt == 0 else f"{rule_prefix}retry{attempt}-"
        pack_name = ctx.unique_name("sim2real-process-pack-")
        template = (
            "Resources:\n"
            "  ProcessCheckRule:\n"
            "    Type: AWS::Config::ConfigRule\n"
            "    Properties:\n"
            f"      ConfigRuleName: {rule_name}\n"
            "      Description: sim2real manual process check\n"
            "      Source:\n"
            "        Owner: AWS\n"
            "        SourceIdentifier: AWS_CONFIG_PROCESS_CHECK\n"
        )
        config.put_conformance_pack(
            ConformancePackName=pack_name,
            TemplateBody=template,
            Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
        )
        ctx.on_cleanup(lambda p=pack_name: _safe(lambda: config.delete_conformance_pack(ConformancePackName=p), "NoSuchConformancePackException", busy=("ResourceInUseException",)))
        try:
            _poll_conformance_pack_status(config, pack_name, "CREATE_COMPLETE", timeout_s=180)
            return _poll_rule_active_by_prefix(config, rule_name, timeout_s=60)
        except AssertionError as exc:
            last_failure = exc
            continue
    assert last_failure is not None
    raise last_failure


def _poll_conformance_pack_status(config, pack_name: str, expected: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = config.describe_conformance_pack_status(ConformancePackNames=[pack_name])
        statuses = resp.get("ConformancePackStatusDetails", [])
        if statuses:
            last = statuses[0]
            if last["ConformancePackState"] == expected:
                return last
            if last["ConformancePackState"] in {"CREATE_FAILED", "DELETE_FAILED"}:
                raise AssertionError(f"conformance pack entered failure state: {last}")
        time.sleep(5)
    raise AssertionError(f"conformance pack {pack_name} never reached {expected!r}, last seen {last!r}")


def _poll_rule_active_by_prefix(config, rule_name_prefix: str, timeout_s: float = 60.0) -> str:
    """Conformance packs may deploy their rules under a modified name (Config
    can suffix conformance-pack-managed rule names); find whichever ACTIVE
    rule was produced from our template rather than assuming an exact name."""
    deadline = time.monotonic() + timeout_s
    last_names: list[str] = []
    while time.monotonic() < deadline:
        matches = []
        paginator = config.get_paginator("describe_config_rules")
        for page in paginator.paginate():
            for rule in page.get("ConfigRules", []):
                if rule["ConfigRuleName"].startswith(rule_name_prefix):
                    matches.append(rule)
        last_names = [r["ConfigRuleName"] for r in matches]
        active = [r for r in matches if r["ConfigRuleState"] == "ACTIVE"]
        if len(active) == 1:
            return active[0]["ConfigRuleName"]
        time.sleep(3)
    raise AssertionError(
        f"no single ACTIVE config rule found with prefix {rule_name_prefix!r}, last seen names {last_names!r}"
    )


def _poll_rule_active(config, rule_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        rules = config.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
        if rules:
            last = rules[0]["ConfigRuleState"]
            if last == "ACTIVE":
                return
        time.sleep(3)
    raise AssertionError(f"config rule {rule_name} never reached ACTIVE, last seen {last!r}")


def _find_result_for_resource(config, rule_name: str, resource_id: str) -> dict[str, Any] | None:
    resp = config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)
    for result in resp.get("EvaluationResults", []):
        qualifier = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
        if qualifier.get("ResourceId") == resource_id:
            return result
    return None


def _poll_for_resource(config, rule_name: str, resource_id: str, timeout_s: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = _find_result_for_resource(config, rule_name, resource_id)
        if result is not None:
            return result
        time.sleep(3)
    raise AssertionError(f"external evaluation for {resource_id} on {rule_name} never appeared")


def _poll_for_absence(config, rule_name: str, resource_id: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = _find_result_for_resource(config, rule_name, resource_id)
        if result is None:
            return
        time.sleep(3)
    raise AssertionError(f"evaluation result for {resource_id} on {rule_name} was not removed by DeleteEvaluationResults")


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
