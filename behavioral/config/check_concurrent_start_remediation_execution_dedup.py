"""concurrent-start-remediation-execution-dedup."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-start-remediation-execution-dedup"
GROUP = "concurrency"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """Two concurrent StartRemediationExecution calls for one resource key: at most one is rejected,
    each accepted call runs its own SSM automation to Success, yet Config tracks a single
    execution record for the key, so the duplicate run is invisible through Config alone."""
    _restore_config_recorder_on_teardown(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    config = ctx.client("config")
    iam = ctx.client("iam")
    sns = ctx.client("sns")

    _ensure_customer_managed_recorder(ctx, config, iam)

    # StartRemediationExecution needs a resource key with a NON_COMPLIANT evaluation result. A
    # CUSTOM_LAMBDA rule that self-reports via PutEvaluations provides one without waiting on
    # Config's resource discovery.
    param_name = ctx.unique_name("/sim2real-config/remdup-")
    ssm = ctx.client("ssm")
    ssm.put_parameter(Name=param_name, Value="false", Type="String")
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_parameter(Name=param_name), "ParameterNotFound"))

    # The automation role is created before the slow Lambda/rule setup: SSM's view of a new role's
    # trust policy lags its creation ("The defined assume role is unable to be assumed"), and no
    # read confirms assumability by a service principal.
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-remduptopic-"),
        Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    role_arn = _create_ssm_automation_role(ctx, iam, topic_arn)
    # The document's 5s aws:sleep step keeps the first execution IN_PROGRESS while the second
    # racing call lands; a single-step document can finish before it does.
    doc_name = _create_remediation_document(ctx)

    lambda_role_arn = _create_lambda_eval_role(ctx, iam)
    function_arn, function_name = _create_evaluator_lambda(ctx, lambda_role_arn)
    _allow_config_to_invoke(ctx, function_name)

    rule_name = ctx.unique_name("sim2real-behav-remdup-")
    _put_lambda_config_rule(ctx, config, rule_name, function_arn, param_name)

    _start_rule_evaluation(config, rule_name)
    _poll_compliance(
        ctx, config, rule_name, account_id, "NON_COMPLIANT", timeout_s=_budget_s(ctx, 180.0)
    )

    put_resp = config.put_remediation_configurations(
        RemediationConfigurations=[
            {
                "ConfigRuleName": rule_name,
                "TargetType": "SSM_DOCUMENT",
                "TargetId": doc_name,
                "Automatic": False,
                "MaximumAutomaticAttempts": 1,
                "RetryAttemptSeconds": 60,
                "Parameters": {
                    "TopicArn": {"StaticValue": {"Values": [topic_arn]}},
                    "Message": {"StaticValue": {"Values": ["sim2real-remediation-dedup-test"]}},
                    "AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}},
                },
            }
        ]
    )
    assert not put_resp.get("FailedBatches"), (
        f"expected the remediation configuration to be accepted with no failed batches, "
        f"got FailedBatches={put_resp.get('FailedBatches')!r}"
    )
    ctx.on_cleanup(lambda: config.delete_remediation_configuration(ConfigRuleName=rule_name))

    resource_key = {"resourceType": "AWS::::Account", "resourceId": account_id}

    def _fire():
        return config.start_remediation_execution(ConfigRuleName=rule_name, ResourceKeys=[resource_key])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_fire) for _ in range(2)]
        responses = [f.result() for f in futures]

    # A FailedItem for any other key would be an unrelated rejection.
    for resp in responses:
        for item in resp.get("FailedItems", []):
            assert item == resource_key, (
                f"a racing StartRemediationExecution reported a FailedItem that is not the "
                f"resource key under test: {item!r} (expected {resource_key!r})"
            )
    rejected_count = sum(1 for resp in responses if resp.get("FailedItems"))
    assert rejected_count <= 1, (
        f"both racing StartRemediationExecution calls were rejected, so nothing was "
        f"deduplicated -- one of them had to be accepted: {responses}"
    )

    # The real effect, read from SSM: one independent automation per ACCEPTED racing call.
    expected_runs = len(responses) - rejected_count
    executions = _wait_automation_executions(
        ctx, doc_name, expected_runs, timeout_s=_budget_s(ctx, 180.0), interval_s=1.0
    )
    assert len(executions) == expected_runs, (
        f"expected one SSM automation execution per accepted StartRemediationExecution call "
        f"({expected_runs} of {len(responses)} accepted) for remediation document "
        f"{doc_name!r}, got {len(executions)}: "
        f"{[(e.get('AutomationExecutionId'), e.get('AutomationExecutionStatus')) for e in executions]}"
    )
    statuses = sorted(e.get("AutomationExecutionStatus") for e in executions)
    assert statuses == ["Success"] * expected_runs, (
        f"every accepted racing call's automation must run to Success -- an accepted call that "
        f"does not execute would make the acceptance meaningless -- got {statuses}"
    )

    # Config's own bookkeeping, by contrast, collapses them: exactly ONE execution record is
    # tracked for the resource key, so the duplicate run is invisible through Config's API.
    # Its State is not asserted: Config can report FAILED (an STS AccessDenied in its own
    # status poll) for automations SSM reports as Success.
    final_state = None
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while time.monotonic() < deadline:
        tracked = config.describe_remediation_execution_status(
            ConfigRuleName=rule_name, ResourceKeys=[resource_key]
        )["RemediationExecutionStatuses"]
        if tracked and tracked[0]["State"] not in ("QUEUED", "IN_PROGRESS"):
            final_state = tracked[0]
            break
        time.sleep(1)
    if final_state is None and _budget_spent(ctx):
        raise TimeoutError("the tracked remediation execution terminal: the run budget ended first; not graded")
    assert final_state is not None, (
        "the tracked remediation execution never reached a terminal state"
    )
    all_statuses = config.describe_remediation_execution_status(
        ConfigRuleName=rule_name, ResourceKeys=[resource_key]
    )["RemediationExecutionStatuses"]
    assert len(all_statuses) == 1, (
        f"expected exactly one remediation execution record for the resource key even though "
        f"{expected_runs} automation(s) actually ran, got {len(all_statuses)}: {all_statuses}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _safe(fn, *gone_codes) -> None:
    """Run a teardown call; return quietly only on the resource's not-found codes."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone_codes:
            raise


def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    # AWS Config delivers snapshot/history objects into this bucket while the recorder
    # runs -- DeleteBucket fails with BucketNotEmpty unless those are removed first.
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _ensure_customer_managed_recorder(ctx, config, iam) -> None:
    existing = config.describe_configuration_recorders()["ConfigurationRecorders"]
    for rec in existing:
        if not rec.get("servicePrincipal"):
            return  # a customer-managed recorder already exists; reuse it, don't own its lifecycle

    role_name = ctx.unique_name("sim2real-behav-config-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})

    # Config validates roleARN against IAM at call time, and IAM's propagation to Config's
    # control plane lags role creation -- retry the actual dependent call (never a blind
    # sleep) until Config accepts the role or the deadline is reached.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": "default",
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
                }
            )
            break
        except config.exceptions.InvalidRoleException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: config.delete_configuration_recorder(ConfigurationRecorderName="default"))

    # StartConfigurationRecorder refuses with NoAvailableDeliveryChannelException unless a
    # delivery channel already exists -- provision the minimal S3-backed one it requires.
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-config-bucket-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _safe(lambda: _empty_and_delete_bucket(s3, bucket_name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real:behavioral-check", "Value": CHECK}]})

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

    channel_name = ctx.unique_name("sim2real-behav-config-channel-")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            config.put_delivery_channel(DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name})
            break
        except config.exceptions.InsufficientDeliveryPolicyException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name))

    config.start_configuration_recorder(ConfigurationRecorderName="default")
    ctx.on_cleanup(lambda: _safe(lambda: config.stop_configuration_recorder(ConfigurationRecorderName="default"), "NoSuchConfigurationRecorderException"))


def _create_lambda_eval_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-lambda-eval-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
            "NoSuchEntity",
        )
    )
    inline_policy_name = ctx.unique_name("sim2real-behav-lambda-eval-policy-")
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["config:PutEvaluations"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ssm:GetParameter"], "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name), "NoSuchEntity"))

    # IAM inline-policy attachment is eventually consistent; poll our own read path (never
    # a blind sleep) until the policy is independently visible before Lambda relies on it.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            iam.get_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
            break
        except iam.exceptions.NoSuchEntityException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    return role_arn


def _create_evaluator_lambda(ctx, role_arn: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-behav-remdup-eval-")
    code = (
        "import json\n"
        "import datetime\n"
        "import boto3\n\n\n"
        "def handler(event, context):\n"
        "    params = json.loads(event.get('ruleParameters') or '{}')\n"
        "    param_name = params.get('ParameterName')\n"
        "    ssm = boto3.client('ssm')\n"
        "    try:\n"
        "        value = ssm.get_parameter(Name=param_name)['Parameter']['Value']\n"
        "    except Exception:\n"
        "        value = 'false'\n"
        "    compliance = 'COMPLIANT' if value == 'true' else 'NON_COMPLIANT'\n"
        "    config = boto3.client('config')\n"
        "    config.put_evaluations(\n"
        "        Evaluations=[{\n"
        "            'ComplianceResourceType': 'AWS::::Account',\n"
        "            'ComplianceResourceId': event['accountId'],\n"
        "            'ComplianceType': compliance,\n"
        "            'Annotation': 'sim2real-remediation-dedup',\n"
        "            'OrderingTimestamp': datetime.datetime.utcnow(),\n"
        "        }],\n"
        "        ResultToken=event['resultToken'],\n"
        "    )\n"
        "    return 'done'\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)

    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                Tags={"sim2real:behavioral-check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _safe(lambda: lam.delete_function(FunctionName=function_name), "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=function_name, WaiterConfig={"Delay": 1, "MaxAttempts": 120}
    )
    return resp["FunctionArn"], function_name


def _allow_config_to_invoke(ctx, function_name: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-config-invoke",
        Action="lambda:InvokeFunction",
        Principal="config.amazonaws.com",
    )


def _put_lambda_config_rule(ctx, config, rule_name: str, function_arn: str, param_name: str) -> None:
    def _put():
        config.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Source": {
                    "Owner": "CUSTOM_LAMBDA",
                    "SourceIdentifier": function_arn,
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            "MessageType": "ScheduledNotification",
                            "MaximumExecutionFrequency": "TwentyFour_Hours",
                        }
                    ],
                },
                "InputParameters": json.dumps({"ParameterName": param_name}),
            },
            Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
        )

    deadline = time.monotonic() + 60.0
    while True:
        try:
            _put()
            break
        except config.exceptions.InsufficientPermissionsException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: config.delete_config_rule(ConfigRuleName=rule_name))


def _start_rule_evaluation(config, rule_name: str) -> None:
    for _ in range(30):
        try:
            config.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
            return
        except config.exceptions.ResourceInUseException:
            time.sleep(1)
    raise AssertionError("could not start config rule evaluation (rule stayed busy)")


def _poll_compliance(ctx, config, rule_name: str, account_id: str, expected: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)
        except Exception:
            resp = {"EvaluationResults": []}
        for result in resp.get("EvaluationResults", []):
            qualifier = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
            if qualifier.get("ResourceId") == account_id:
                last = result["ComplianceType"]
                if last == expected:
                    return result
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"compliance for account {account_id} reaching {expected!r}: the run budget ended first; not graded")
    raise AssertionError(f"compliance for account {account_id} never reached {expected!r}, last seen {last!r}")


def _create_remediation_document(ctx) -> str:
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-behav-remdup-doc-")
    content = {
        "schemaVersion": "0.3",
        "assumeRole": "{{ AutomationAssumeRole }}",
        "parameters": {
            "AutomationAssumeRole": {"type": "String"},
            "TopicArn": {"type": "String"},
            "Message": {"type": "String"},
        },
        "mainSteps": [
            {"name": "HoldInProgress", "action": "aws:sleep", "inputs": {"Duration": "PT5S"}},
            {
                "name": "Publish",
                "action": "aws:executeAwsApi",
                "inputs": {
                    "Service": "sns",
                    "Api": "Publish",
                    "TopicArn": "{{ TopicArn }}",
                    "Message": "{{ Message }}",
                },
            },
        ],
    }
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(content),
        Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_document(Name=doc_name), "InvalidDocument"))
    return doc_name


def _wait_automation_executions(ctx, doc_name: str, expected: int, timeout_s: float, interval_s: float) -> list[dict]:
    """Poll until *expected* executions of *doc_name* exist and all are settled, then return them.

    At the deadline it returns what it has, so the caller reports the real count."""
    deadline = time.monotonic() + timeout_s
    found: list[dict] = []
    while True:
        found = _automation_executions(ctx, doc_name)
        settled = [
            e
            for e in found
            if e.get("AutomationExecutionStatus")
            not in ("Pending", "InProgress", "Waiting", "Cancelling")
        ]
        if len(found) >= expected and len(settled) == len(found):
            return found
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{expected} settled automation execution(s) of {doc_name!r}: the run budget ended first; not graded")
            return found
        time.sleep(interval_s)


def _automation_executions(ctx, doc_name: str) -> list[dict]:
    """Every SSM automation execution launched from *doc_name*. The document name is unique
    per run (ctx.unique_name), so this is scoped to this check's own remediation."""
    ssm = ctx.client("ssm")
    found: list[dict] = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = ssm.describe_automation_executions(
            Filters=[{"Key": "DocumentNamePrefix", "Values": [doc_name]}], **kwargs
        )
        found.extend(page.get("AutomationExecutionMetadataList", []))
        next_token = page.get("NextToken")
        if not next_token:
            return found


def _create_ssm_automation_role(ctx, iam, topic_arn: str) -> str:
    role_name = ctx.unique_name("sim2real-behav-ssm-role-")
    # Both principals: SSM assumes this role to run the automation and Config assumes it to poll
    # that automation; with ssm.amazonaws.com alone Config's poll fails with an STS AccessDenied.
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": ["ssm.amazonaws.com", "config.amazonaws.com"]
                },
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    policy_name = ctx.unique_name("sim2real-behav-ssm-policy-")
    # Config starts and polls the automation under this role, so sns:Publish alone is not enough:
    # Config's GetAutomationExecution poll fails with AccessDenied.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn},
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:StartAutomationExecution",
                    "ssm:GetAutomationExecution",
                    "ssm:DescribeAutomationExecutions",
                    "ssm:DescribeAutomationStepExecutions",
                    "ssm:StopAutomationExecution",
                ],
                "Resource": "*",
            },
            # PassRole/AssumeRole on itself: the document's `assumeRole` makes the session
            # already running under this role re-assume it for the step.
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole", "sts:AssumeRole"],
                "Resource": role_arn,
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    # IAM inline-policy attachment is eventually consistent; poll our own read path (never
    # a blind sleep) until the policy is independently visible before it is relied on.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            break
        except iam.exceptions.NoSuchEntityException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    return role_arn


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
