"""change-triggered-custom-rule-is-push-invoked-with-a-real-configuration-item."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-triggered-custom-rule-is-push-invoked-with-a-real-configuration-item"
GROUP = "e2e"
SERVICES = ["config", "lambda", "sqs"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# A fresh allSupported recorder records the queue's first configuration item within minutes, and
# the first push evaluation follows PutConfigRule within ~20 s. A recordingGroup limited to
# AWS::SQS::Queue can record nothing at all, so the recorder uses allSupported. The flip budget is
# larger because the second push waits on Config recording the changed resource.
_CI_BUDGET_S = 1400.0
_FIRST_EVAL_BUDGET_S = 300.0
_FLIP_BUDGET_S = 600.0
_POLL_INTERVAL_S = 2.0

_CONFIG_ROLE_NAME = "sim2real-behav-config-role"
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_LAMBDA_BASIC_POLICY_ARN = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
)
_INITIAL_TIMEOUT = "30"
_FIXED_TIMEOUT = "60"

# The evaluator. It reads the configurationItem Config HANDED it -- the check never passes the
# queue's state to it -- and echoes the fields back through Annotation so the assertions can
# grade what Config pushed rather than what the function guessed.
_HANDLER_SOURCE = """
import json
import boto3


def handler(event, context):
    cfg = boto3.client("config")
    invoking = json.loads(event["invokingEvent"])
    item = invoking.get("configurationItem") or {}
    configuration = item.get("configuration")
    if isinstance(configuration, str):
        configuration = json.loads(configuration)
    configuration = configuration or {}
    observed = str(configuration.get("VisibilityTimeout"))
    annotation = ("observed=%s ciStatus=%s msgType=%s rid=%s" % (
        observed, item.get("configurationItemStatus"), invoking.get("messageType"),
        item.get("resourceId")))[:255]
    cfg.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": item.get("resourceType", "AWS::SQS::Queue"),
            "ComplianceResourceId": item.get("resourceId", "unknown"),
            "ComplianceType": "COMPLIANT" if observed == "60" else "NON_COMPLIANT",
            "Annotation": annotation,
            "OrderingTimestamp": item.get("configurationItemCaptureTime"),
        }],
        ResultToken=event["resultToken"],
    )
    return annotation
"""

_BUCKET_POLICY_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSConfigBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {"Service": "config.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::BUCKET",
        },
        {
            "Sid": "AWSConfigBucketExistenceCheck",
            "Effect": "Allow",
            "Principal": {"Service": "config.amazonaws.com"},
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::BUCKET",
        },
        {
            "Sid": "AWSConfigBucketDelivery",
            "Effect": "Allow",
            "Principal": {"Service": "config.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::BUCKET/*",
            "Condition": {
                "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
            },
        },
    ],
}


def _capped(ctx, budget_s):
    """*budget_s*, capped by the time the run has left so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, max(0.0, left - 10.0))


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            if code not in (
                "ThrottlingException",
                "TooManyRequestsException",
                "LimitExceededException",
            ):
                raise
            last = err
            time.sleep(base_delay * (attempt + 1))
    raise last


def _ensure_config_role(ctx):
    """One deterministic recorder role, created if absent, rather than adopting any role that
    trusts config.amazonaws.com."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]["Arn"]
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    arn = iam.create_role(
        RoleName=_CONFIG_ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(
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
        ),
        Description="sim2real behavioral fidelity probe role for AWS Config",
        Tags=[{"Key": "sim2real", "Value": "config-recorder-role"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=_CONFIG_ROLE_NAME, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
    )
    # _create_recorder retries until the role has propagated. The role is shared and not deleted.
    return arn


def _clear_recorders(ctx):
    """A region holds ONE configuration recorder and ONE delivery channel, so a leftover one is a
    precondition to remove, not cleanup.

    Order matters: DeleteDeliveryChannel on the last channel fails while a recorder is running, so
    recorders are stopped first, then the channels go, then the recorders."""
    cfg = ctx.client("config")
    recorders = [
        r["name"]
        for r in cfg.describe_configuration_recorders().get(
            "ConfigurationRecorders", []
        )
    ]
    for name in recorders:
        try:
            _retry_throttled(
                lambda n=name: cfg.stop_configuration_recorder(
                    ConfigurationRecorderName=n
                )
            )
        except ClientError:
            pass
    for channel in cfg.describe_delivery_channels().get("DeliveryChannels", []):
        try:
            _retry_throttled(
                lambda n=channel["name"]: cfg.delete_delivery_channel(
                    DeliveryChannelName=n
                )
            )
        except ClientError:
            pass
    for name in recorders:
        try:
            _retry_throttled(
                lambda n=name: cfg.delete_configuration_recorder(
                    ConfigurationRecorderName=n
                )
            )
        except ClientError:
            pass


def _empty_and_delete_bucket(ctx, bucket):
    """Empty and delete the delivery bucket, retrying because Config keeps writing snapshots into
    it; bounded at 30 s because all cleanups share a 60 s ceiling."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + 30.0
    last = None
    while True:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in list(page.get("Versions", [])) + list(
                page.get("DeleteMarkers", [])
            ):
                s3.delete_object(
                    Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"]
                )
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "BucketNotEmpty":
                raise
            if time.monotonic() > deadline:
                raise last
            time.sleep(3.0)


def _create_recorder(ctx, name, role_arn):
    """PutConfigurationRecorder validates that Config can assume the role, which fails until a
    freshly created role has propagated, so it is retried until a deadline."""
    cfg = ctx.client("config")
    last = None
    deadline = time.monotonic() + _capped(ctx, 180.0)
    while True:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": name,
                        "roleARN": role_arn,
                        "recordingGroup": {
                            "allSupported": True,
                            "includeGlobalResourceTypes": False,
                        },
                    }
                )
            )
            return
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") not in (
                "InsufficientPermissionsException",
                "AccessDeniedException",
            ):
                raise
            last = err
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"PutConfigurationRecorder({name}) never succeeded: {last}"
                ) from err
            time.sleep(2.0)


def _create_delivery_channel(ctx, name, bucket):
    """A freshly written bucket policy is eventually consistent; Config rejects a delivery
    channel whose bucket policy has not propagated with InsufficientDeliveryPolicyException."""
    cfg = ctx.client("config")
    last = None
    for attempt in range(8):
        try:
            _retry_throttled(
                lambda: cfg.put_delivery_channel(
                    DeliveryChannel={"name": name, "s3BucketName": bucket}
                )
            )
            return
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != (
                "InsufficientDeliveryPolicyException"
            ):
                raise
            last = err
            time.sleep(3 * (attempt + 1))
    raise AssertionError(f"PutDeliveryChannel({name}) never succeeded: {last}")


def _history(ctx, queue_url):
    cfg = ctx.client("config")
    try:
        return cfg.get_resource_config_history(
            resourceType="AWS::SQS::Queue", resourceId=queue_url, limit=50
        ).get("configurationItems", [])
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotDiscoveredException":
            return []
        raise


def _results(ctx, rule_name):
    """Page the rule's evaluation results to exhaustion."""
    cfg = ctx.client("config")
    out = []
    token = None
    for _ in range(20):
        kwargs = {"ConfigRuleName": rule_name, "Limit": 100}
        if token:
            kwargs["NextToken"] = token
        resp = cfg.get_compliance_details_by_config_rule(**kwargs)
        out.extend(resp.get("EvaluationResults", []))
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _delete_config_rule(ctx, rule_name):
    """DeleteConfigRule and return without waiting: all cleanups share a 60 s ceiling, and deleting
    the Lambda while the rule is still DELETING is accepted."""
    cfg = ctx.client("config")
    try:
        _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchConfigRuleException":
            raise


def _annotation_field(annotation, key):
    for token in (annotation or "").split(" "):
        if token.startswith(key + "="):
            return token[len(key) + 1 :]
    return None


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder",
)
def run(ctx) -> None:
    """A ConfigurationItemChangeNotification custom rule is invoked by Config unprompted with a real
    configuration item (discovery status, string VisibilityTimeout, no relationships), and changing
    the queue flips the verdict again without StartConfigRulesEvaluation.

    Reference: https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_lambda-functions.html
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")

    role_arn = _ensure_config_role(ctx)
    _clear_recorders(ctx)

    bucket = ctx.unique_name("sim2real-behav-cfg-delivery-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK[:60]}]}
    )
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(_BUCKET_POLICY_TEMPLATE).replace("BUCKET", bucket),
    )

    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder, role_arn)
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(
                ConfigurationRecorderName=recorder
            )
        )
    )
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket)
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel)
        )
    )
    _retry_throttled(
        lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=recorder)
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder)
        )
    )

    queue_name = ctx.unique_name("sim2real-behav-f4cfgq-")
    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"VisibilityTimeout": _INITIAL_TIMEOUT},
        tags={"sim2real": "config-change-triggered-push"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    t0 = time.monotonic()
    items = []
    ci_budget = _capped(ctx, _CI_BUDGET_S)
    while time.monotonic() - t0 < ci_budget:
        items = _retry_throttled(lambda: _history(ctx, queue_url))
        if items:
            break
        time.sleep(_POLL_INTERVAL_S)
    ci_latency = time.monotonic() - t0
    statuses = [
        {
            k: s.get(k)
            for k in (
                "name",
                "recording",
                "lastStatus",
                "lastErrorCode",
                "lastErrorMessage",
            )
        }
        for s in cfg.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[recorder]
        ).get("ConfigurationRecordersStatus", [])
    ]
    assert items, (
        f"{DATAPLANE_MARKER}: the configuration recorder produced no configuration item for "
        f"queue {queue_url!r} in {ci_latency:.0f}s. Recorder status: {statuses!r}. Real AWS "
        f"produced the first item in 60 s. Without a recorded item there is nothing for Config "
        f"to push, so every assertion below is unreachable"
    )
    discovered = items[-1]
    assert discovered["configurationItemStatus"] == "ResourceDiscovered", (
        f"the earliest item for a queue created under a running recorder must be "
        f"ResourceDiscovered, got {discovered['configurationItemStatus']!r} (history was "
        f"{[i['configurationItemStatus'] for i in items]!r})"
    )
    assert (
        json.loads(discovered["configuration"])["VisibilityTimeout"] == _INITIAL_TIMEOUT
    ), (
        f"the recorded configuration does not carry the queue's live VisibilityTimeout as the "
        f"STRING {_INITIAL_TIMEOUT!r}: {discovered['configuration']!r}"
    )
    assert discovered["relationships"] == [], (
        f"an SQS queue's configuration item relates to nothing, so relationships must be empty; "
        f"got {discovered['relationships']!r}"
    )

    # --- The evaluator.
    fn_role = ctx.unique_name("sim2real-behav-f4cfgfn-")
    fn_role_arn = iam.create_role(
        RoleName=fn_role,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description="sim2real-behav Config change-triggered evaluator",
        Tags=[{"Key": "sim2real", "Value": "config-change-triggered-push"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fn_role))
    iam.attach_role_policy(RoleName=fn_role, PolicyArn=_LAMBDA_BASIC_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=fn_role, PolicyArn=_LAMBDA_BASIC_POLICY_ARN
        )
    )
    iam.put_role_policy(
        RoleName=fn_role,
        PolicyName="put-evaluations",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["config:PutEvaluations"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=fn_role, PolicyName="put-evaluations")
    )

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _HANDLER_SOURCE)
    fn_name = ctx.unique_name("sim2real-behav-f4cfgeval-")
    # CreateFunction rejects a role that has not propagated with InvalidParameterValueException.
    deadline = time.monotonic() + 180.0
    fn_arn = None
    last = None
    while time.monotonic() < deadline:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=fn_role_arn,
                Handler="handler.handler",
                Code={"ZipFile": archive.getvalue()},
                Timeout=60,
                Tags={"sim2real": "config-change-triggered-push"},
            )["FunctionArn"]
            break
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(2.0)
    assert fn_arn, f"CreateFunction never succeeded: {last}"

    def _delete_fn_log_group():
        try:
            ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    # Registered before delete_function so LIFO runs the function delete FIRST: Config can still
    # be retrying a push invocation right up to teardown, and deleting the log group first lets
    # that retry recreate it between the two deletes.
    ctx.on_cleanup(_delete_fn_log_group)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    # PutConfigRule fails with InvalidParameterValueException ("The specified AWS Lambda function
    # is not in Active state") while the function is Pending, so wait on its State.
    deadline = time.monotonic() + 180.0
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name).get("State")
        if state == "Active":
            break
        time.sleep(2.0)
    assert state == "Active", (
        f"function {fn_name!r} never became Active (last state {state!r})"
    )

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-behav-config-invoke",
        Action="lambda:InvokeFunction",
        Principal="config.amazonaws.com",
        SourceAccount=ctx.client("sts").get_caller_identity()["Account"],
    )

    rule_name = ctx.unique_name("sim2real-behav-f4cfgrule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Scope": {
                "ComplianceResourceTypes": ["AWS::SQS::Queue"],
                "ComplianceResourceId": queue_url,
            },
            "Source": {
                "Owner": "CUSTOM_LAMBDA",
                "SourceIdentifier": fn_arn,
                "SourceDetails": [
                    {
                        "EventSource": "aws.config",
                        "MessageType": "ConfigurationItemChangeNotification",
                    }
                ],
            },
        }
    )
    ctx.on_cleanup(lambda: _delete_config_rule(ctx, rule_name))

    # ===== From here to the end of the check, Config initiates. No StartConfigRulesEvaluation.
    t0 = time.monotonic()
    first = []
    first_budget = _capped(ctx, _FIRST_EVAL_BUDGET_S)
    while time.monotonic() - t0 < first_budget:
        first = [
            r
            for r in _retry_throttled(lambda: _results(ctx, rule_name))
            if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"][
                "ResourceId"
            ]
            == queue_url
        ]
        if first:
            break
        time.sleep(_POLL_INTERVAL_S)
    push_latency = time.monotonic() - t0
    status = cfg.describe_config_rule_evaluation_status(
        ConfigRuleNames=[rule_name]
    ).get("ConfigRulesEvaluationStatus", [])
    assert first, (
        f"{DATAPLANE_MARKER}: AWS Config never invoked the change-triggered rule. In "
        f"{push_latency:.0f}s no evaluation result appeared for queue {queue_url!r} under rule "
        f"{rule_name!r}, and this check never called StartConfigRulesEvaluation. Rule evaluation "
        f"status: {json.dumps(status, default=str)[:600]}. Real AWS pushed the first evaluation "
        f"~20 s after PutConfigRule. A target that only serves the PULL path has nothing here"
    )
    first_result = first[0]
    assert first_result["ComplianceType"] == "NON_COMPLIANT", (
        f"the first pushed verdict is {first_result['ComplianceType']!r}; the queue was created "
        f"with VisibilityTimeout {_INITIAL_TIMEOUT!r} and the evaluator returns COMPLIANT only "
        f"for {_FIXED_TIMEOUT!r}"
    )
    annotation = first_result.get("Annotation")
    assert _annotation_field(annotation, "msgType") == (
        "ConfigurationItemChangeNotification"
    ), (
        f"the evaluator saw invokingEvent.messageType "
        f"{_annotation_field(annotation, 'msgType')!r}, expected "
        f"ConfigurationItemChangeNotification. This is the whole claim: a target that delivers a "
        f"ScheduledNotification instead has not implemented the push trigger"
    )
    assert _annotation_field(annotation, "observed") == _INITIAL_TIMEOUT, (
        f"the evaluator read VisibilityTimeout {_annotation_field(annotation, 'observed')!r} out "
        f"of the configurationItem Config handed it, expected the queue's live value "
        f"{_INITIAL_TIMEOUT!r}. The check never told the function anything, so this grades the "
        f"item Config CONSTRUCTED"
    )
    assert _annotation_field(annotation, "ciStatus") == "ResourceDiscovered", (
        f"the pushed configurationItem's configurationItemStatus was "
        f"{_annotation_field(annotation, 'ciStatus')!r}, expected ResourceDiscovered -- a target "
        f"that pushes an item with no status, or a fabricated one, fails here"
    )
    assert _annotation_field(annotation, "rid") == queue_url, (
        f"the pushed configurationItem's resourceId was "
        f"{_annotation_field(annotation, 'rid')!r}, expected the queue that changed "
        f"({queue_url!r}) -- Config keys an SQS queue by its URL, not its name"
    )
    qualifier = first_result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
    assert qualifier["EvaluationMode"] == "DETECTIVE", (
        f"EvaluationMode is {qualifier['EvaluationMode']!r}, expected DETECTIVE for a rule "
        f"driven by recorded configuration items"
    )
    assert qualifier["ResourceType"] == "AWS::SQS::Queue", (
        f"ResourceType is {qualifier['ResourceType']!r}, expected AWS::SQS::Queue"
    )

    # --- Change the resource out of band. Config must notice by itself.
    sqs.set_queue_attributes(
        QueueUrl=queue_url, Attributes={"VisibilityTimeout": _FIXED_TIMEOUT}
    )

    t0 = time.monotonic()
    second = None
    flip_budget = _capped(ctx, _FLIP_BUDGET_S)
    while time.monotonic() - t0 < flip_budget:
        for result in _retry_throttled(lambda: _results(ctx, rule_name)):
            qual = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
            if qual["ResourceId"] != queue_url:
                continue
            if (
                result["ComplianceType"] == "COMPLIANT"
                and _annotation_field(result.get("Annotation"), "observed")
                == _FIXED_TIMEOUT
            ):
                second = result
                break
        if second is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    flip_latency = time.monotonic() - t0

    assert second is not None, (
        f"{DATAPLANE_MARKER}: after VisibilityTimeout was changed {_INITIAL_TIMEOUT} -> "
        f"{_FIXED_TIMEOUT} out of band, Config never re-evaluated the queue. {flip_latency:.0f}s "
        f"elapsed with no COMPLIANT result carrying observed={_FIXED_TIMEOUT}; the latest "
        f"results were "
        f"{[(r['ComplianceType'], r.get('Annotation')) for r in _results(ctx, rule_name)]!r} and "
        f"this check never called StartConfigRulesEvaluation. The change-detection loop -- "
        f"notice a SetQueueAttributes on a recorded resource, build a new configuration item, "
        f"push it -- is what near-real-time compliance is sold on"
    )
    assert second["ResultRecordedTime"] > first_result["ResultRecordedTime"], (
        f"the flipped verdict's ResultRecordedTime {second['ResultRecordedTime']!r} is not "
        f"strictly later than the first's {first_result['ResultRecordedTime']!r}, so it is not a "
        f"new evaluation"
    )
    assert _annotation_field(second.get("Annotation"), "msgType") == (
        "ConfigurationItemChangeNotification"
    ), (
        f"the second, change-driven invocation carried messageType "
        f"{_annotation_field(second.get('Annotation'), 'msgType')!r}, expected "
        f"ConfigurationItemChangeNotification"
    )
    assert _annotation_field(second.get("Annotation"), "ciStatus") == "OK", (
        f"the CHANGE item's configurationItemStatus was "
        f"{_annotation_field(second.get('Annotation'), 'ciStatus')!r}, expected OK -- the first "
        f"item was ResourceDiscovered, so a target reusing one status for both fails one of the "
        f"two assertions"
    )

    # --- Config recorded the change it noticed, and the two compliance indexes agree.
    history = _history(ctx, queue_url)
    timeouts = [
        json.loads(i["configuration"])["VisibilityTimeout"]
        for i in sorted(history, key=lambda i: i["configurationItemCaptureTime"])
    ]
    assert timeouts[0] == _INITIAL_TIMEOUT and timeouts[-1] == _FIXED_TIMEOUT, (
        f"the recorded configuration-item history for the queue reads {timeouts!r}; it must "
        f"start at {_INITIAL_TIMEOUT!r} and end at {_FIXED_TIMEOUT!r} in "
        f"configurationItemCaptureTime order -- Config must have recorded the change it then "
        f"evaluated"
    )
    by_resource = cfg.get_compliance_details_by_resource(
        ResourceType="AWS::SQS::Queue", ResourceId=queue_url
    ).get("EvaluationResults", [])
    matching = [
        r
        for r in by_resource
        if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"].get(
            "ConfigRuleName"
        )
        == rule_name
    ]
    assert matching and matching[0]["ComplianceType"] == "COMPLIANT", (
        f"GetComplianceDetailsByResource disagrees with GetComplianceDetailsByConfigRule on the "
        f"final verdict for {queue_url!r}: the by-resource index says "
        f"{[r['ComplianceType'] for r in matching]!r}, the by-rule index says COMPLIANT"
    )


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
