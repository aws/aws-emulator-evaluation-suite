"""change-triggered-rule-creation-is-denied-when-config-cannot-invoke-the-evaluator."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-triggered-rule-creation-is-denied-when-config-cannot-invoke-the-evaluator"
GROUP = "data-plane"
SERVICES = ["config", "lambda", "sqs"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# A recorder scoped to resourceTypes=[AWS::SQS::Queue] records no configuration item at all
# while reporting SUCCESS, so the recorder uses allSupported. A fresh recorder takes about
# 1-2 min to record the queue and a new rule about 20 s to be push-invoked; budgets are ~2-5x that.
# Config validates invokability at PutConfigRule time, so the rule is refused outright.
_CI_BUDGET_S = 300.0
_FIRST_EVAL_BUDGET_S = 300.0
_POLL_INTERVAL_S = 10.0

_EXPECTED_CODE = "InsufficientPermissionsException"

_CONFIG_ROLE_NAME = "sim2real-behav-config-role"
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_LAMBDA_BASIC_POLICY_ARN = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
)
_INITIAL_TIMEOUT = "30"

# The evaluator echoes the configurationItem Config pushed to it back through Annotation.
_HANDLER_SOURCE = '''
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
'''

_BUCKET_POLICY_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "AWSConfigBucketPermissionsCheck", "Effect": "Allow",
         "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:GetBucketAcl",
         "Resource": "arn:aws:s3:::BUCKET"},
        {"Sid": "AWSConfigBucketExistenceCheck", "Effect": "Allow",
         "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:ListBucket",
         "Resource": "arn:aws:s3:::BUCKET"},
        {"Sid": "AWSConfigBucketDelivery", "Effect": "Allow",
         "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::BUCKET/*",
         "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
    ],
}


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException",
                            "LimitExceededException"):
                raise
            last = err
            time.sleep(base_delay * (attempt + 1))
    raise last


def _ensure_config_role(ctx):
    """One deterministic recorder role, created if absent, rather than reusing any role that
    trusts config.amazonaws.com."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]["Arn"]
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    arn = iam.create_role(
        RoleName=_CONFIG_ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "config.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real behavioral fidelity probe role for AWS Config",
        Tags=[{"Key": "sim2real", "Value": "config-recorder-role"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=_CONFIG_ROLE_NAME,
                           PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    # Role propagation is waited out by the bounded retry in _create_recorder. The role is
    # shared and deliberately not deleted.
    return arn


def _clear_recorders(ctx):
    """Remove any existing recorder and delivery channel (one of each per Region).

    Order matters: deleting the last channel while a recorder runs fails
    LastDeliveryChannelDeleteFailedException, so recorders stop first."""
    cfg = ctx.client("config")
    recorders = [r["name"] for r
                 in cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])]
    for name in recorders:
        try:
            _retry_throttled(
                lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n)
            )
        except ClientError:
            pass
    for channel in cfg.describe_delivery_channels().get("DeliveryChannels", []):
        try:
            _retry_throttled(
                lambda n=channel["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n)
            )
        except ClientError:
            pass
    for name in recorders:
        try:
            _retry_throttled(
                lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n)
            )
        except ClientError:
            pass


def _empty_and_delete_bucket(ctx, bucket):
    """Empty and delete the delivery bucket, retrying because Config keeps writing into it.
    Bounded at 30 s because all of a check's cleanups share a 60 s ceiling."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + 30.0
    last = None
    while True:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", [])):
                s3.delete_object(Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"])
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
    """PutConfigurationRecorder, retried until a freshly created role is assumable by Config."""
    cfg = ctx.client("config")
    last = None
    for attempt in range(8):
        try:
            _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder={
                "name": name, "roleARN": role_arn,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }))
            return
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") not in (
                    "InsufficientPermissionsException", "AccessDeniedException"):
                raise
            last = err
            time.sleep(5 * (attempt + 1))
    raise AssertionError(f"PutConfigurationRecorder({name}) never succeeded: {last}")


def _create_delivery_channel(ctx, name, bucket):
    """A freshly written bucket policy is eventually consistent; Config rejects a delivery
    channel whose bucket policy has not propagated with InsufficientDeliveryPolicyException."""
    cfg = ctx.client("config")
    last = None
    for attempt in range(8):
        try:
            _retry_throttled(lambda: cfg.put_delivery_channel(
                DeliveryChannel={"name": name, "s3BucketName": bucket}
            ))
            return
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != (
                    "InsufficientDeliveryPolicyException"):
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
    """DeleteConfigRule without waiting for DELETING to finish: cleanups share a 60 s budget,
    and deleting the Lambda while the rule is still DELETING is accepted."""
    cfg = ctx.client("config")
    try:
        _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchConfigRuleException":
            raise


def _annotation_field(annotation, key):
    for token in (annotation or "").split(" "):
        if token.startswith(key + "="):
            return token[len(key) + 1:]
    return None


def _error_code(fn):
    """The (code, message) a call raised; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"PutConfigRule was expected to be refused with {_EXPECTED_CODE} because AWS Config "
        f"cannot invoke the evaluator, and instead SUCCEEDED, returning {result!r}. A target that "
        f"accepts a change-triggered rule pointing at a function it has no permission to invoke "
        f"has deferred a hard failure into a compliance dashboard that will read green forever"
    )


def _rule_names(ctx):
    """Every config rule name, paged to exhaustion."""
    cfg = ctx.client("config")
    names = []
    token = None
    for _ in range(20):
        kwargs = {"NextToken": token} if token else {}
        resp = cfg.describe_config_rules(**kwargs)
        names.extend(r["ConfigRuleName"] for r in resp.get("ConfigRules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutConfigRule for a change-triggered rule whose Lambda lacks a config.amazonaws.com invoke
    grant fails InsufficientPermissionsException and creates nothing; after AddPermission the same
    call succeeds and Config push-invokes the rule with a ConfigurationItemChangeNotification.

    Reference: https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_lambda-functions.html
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

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
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder)
    ))
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket)
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel)
    ))
    _retry_throttled(
        lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=recorder)
    )
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=recorder)
    ))

    queue_name = ctx.unique_name("sim2real-behav-f4cfgnq-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, Attributes={"VisibilityTimeout": _INITIAL_TIMEOUT},
        tags={"sim2real": "config-rule-creation-denied"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    t0 = time.monotonic()
    items = []
    while time.monotonic() - t0 < _CI_BUDGET_S:
        items = _history(ctx, queue_url)
        if items:
            break
        time.sleep(_POLL_INTERVAL_S)
    ci_latency = time.monotonic() - t0
    statuses = [
        {k: s.get(k) for k in ("name", "recording", "lastStatus", "lastErrorCode")}
        for s in cfg.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[recorder]
        ).get("ConfigurationRecordersStatus", [])
    ]
    assert items, (
        f"{DATAPLANE_MARKER}: the configuration recorder produced no configuration item for "
        f"queue {queue_url!r} in {ci_latency:.0f}s (recorder status {statuses!r}). Real AWS "
        f"produced the first item in 60-136 s. The setup this negative breaks one thing inside "
        f"never came up, so the rejection below would not be about the permission"
    )

    fn_role = ctx.unique_name("sim2real-behav-f4cfgnfn-")
    fn_role_arn = iam.create_role(
        RoleName=fn_role,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-behav Config change-triggered evaluator (denial scenario)",
        Tags=[{"Key": "sim2real", "Value": "config-rule-creation-denied"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fn_role))
    iam.attach_role_policy(RoleName=fn_role, PolicyArn=_LAMBDA_BASIC_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=fn_role, PolicyArn=_LAMBDA_BASIC_POLICY_ARN)
    )
    iam.put_role_policy(
        RoleName=fn_role, PolicyName="put-evaluations",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["config:PutEvaluations"],
                           "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=fn_role, PolicyName="put-evaluations")
    )

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _HANDLER_SOURCE)
    fn_name = ctx.unique_name("sim2real-behav-f4cfgneval-")
    deadline = time.monotonic() + 180.0
    fn_arn = None
    last = None
    while time.monotonic() < deadline:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn_name, Runtime="python3.12", Role=fn_role_arn,
                Handler="handler.handler", Code={"ZipFile": archive.getvalue()}, Timeout=60,
                Tags={"sim2real": "config-rule-creation-denied"},
            )["FunctionArn"]
            break
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(5.0)
    assert fn_arn, f"CreateFunction never succeeded: {last}"
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    deadline = time.monotonic() + 180.0
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name).get("State")
        if state == "Active":
            break
        time.sleep(4.0)
    assert state == "Active", f"function {fn_name!r} never became Active (last state {state!r})"

    # The missing config.amazonaws.com invoke statement is the one broken thing.
    policy_before = None
    try:
        policy_before = lam.get_policy(FunctionName=fn_name)["Policy"]
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", err
    assert policy_before is None, (
        f"setup: the evaluator must start with no resource policy at all, so the refusal below "
        f"is caused by the missing statement; got {policy_before!r}"
    )

    rule_name = ctx.unique_name("sim2real-behav-f4cfgnrule-")
    rule_body = {
        "ConfigRuleName": rule_name,
        "Scope": {"ComplianceResourceTypes": ["AWS::SQS::Queue"],
                  "ComplianceResourceId": queue_url},
        "Source": {"Owner": "CUSTOM_LAMBDA", "SourceIdentifier": fn_arn,
                   "SourceDetails": [{"EventSource": "aws.config",
                                      "MessageType":
                                          "ConfigurationItemChangeNotification"}]},
    }
    code, message = _error_code(lambda: cfg.put_config_rule(ConfigRule=dict(rule_body)))
    assert code == _EXPECTED_CODE, (
        f"PutConfigRule for an uninvokable evaluator was refused with {code!r}, expected exactly "
        f"{_EXPECTED_CODE!r}. Message was {message!r}"
    )
    assert fn_arn in message, (
        f"the refusal must name the function it could not invoke; got {message!r}"
    )
    assert "cannot be invoked" in message, (
        f"the refusal must say the function cannot be invoked rather than blaming the rule; got "
        f"{message!r}"
    )

    # --- Effect absent: no rule, and no evaluation for the queue.
    assert rule_name not in _rule_names(ctx), (
        f"the refused rule {rule_name!r} exists in DescribeConfigRules anyway. A target that "
        f"raises the error and stores the rule leaves a rule that will never evaluate anything"
    )
    describe_code, _ = _error_code(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name])
    )
    assert describe_code == "NoSuchConfigRuleException", (
        f"DescribeConfigRules for the refused rule reported {describe_code!r}, expected "
        f"NoSuchConfigRuleException"
    )
    stale = [r for r in cfg.get_compliance_details_by_resource(
        ResourceType="AWS::SQS::Queue", ResourceId=queue_url
    ).get("EvaluationResults", [])
        if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"].get("ConfigRuleName")
        == rule_name]
    assert stale == [], (
        f"an evaluation result exists for the refused rule: {stale!r}. Nothing was ever "
        f"evaluated, so nothing may be recorded"
    )

    # --- Positive control: add the ONE missing statement, repeat the identical call.
    lam.add_permission(
        FunctionName=fn_name, StatementId="sim2real-behav-config-invoke",
        Action="lambda:InvokeFunction", Principal="config.amazonaws.com",
        SourceAccount=account,
    )
    # The resource policy is eventually consistent; retry past the code the negative asserts.
    deadline = time.monotonic() + 120.0
    created = False
    last = None
    while time.monotonic() < deadline:
        try:
            cfg.put_config_rule(ConfigRule=dict(rule_body))
            created = True
            break
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != _EXPECTED_CODE:
                raise
            time.sleep(5.0)
    if created:
        ctx.on_cleanup(lambda: _delete_config_rule(ctx, rule_name))
    assert created, (
        f"after granting config.amazonaws.com lambda:InvokeFunction on {fn_name!r}, the "
        f"identical PutConfigRule still failed: {last!r}. Then the refusal above was not about "
        f"the permission and this check proves nothing"
    )
    assert rule_name in _rule_names(ctx), (
        f"the accepted rule {rule_name!r} is absent from DescribeConfigRules"
    )

    # The accepted rule must be push-invoked; StartConfigRulesEvaluation is never called.
    t0 = time.monotonic()
    results = []
    while time.monotonic() - t0 < _FIRST_EVAL_BUDGET_S:
        results = [r for r in _results(ctx, rule_name)
                   if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
                   == queue_url]
        if results:
            break
        time.sleep(_POLL_INTERVAL_S)
    push_latency = time.monotonic() - t0
    assert results, (
        f"{DATAPLANE_MARKER}: the rule Config ACCEPTED was never invoked. {push_latency:.0f}s "
        f"elapsed with no evaluation result for {queue_url!r}, and this check never called "
        f"StartConfigRulesEvaluation. Real AWS pushed the first evaluation ~20 s after "
        f"PutConfigRule. Without this leg the refusal above is indistinguishable from a target "
        f"that refuses every change-triggered rule"
    )
    assert results[0]["ComplianceType"] == "NON_COMPLIANT", (
        f"the pushed verdict is {results[0]['ComplianceType']!r}; the queue's VisibilityTimeout "
        f"is {_INITIAL_TIMEOUT!r} and the evaluator returns COMPLIANT only for '60'"
    )
    annotation = results[0].get("Annotation")
    assert _annotation_field(annotation, "msgType") == (
        "ConfigurationItemChangeNotification"
    ), (
        f"the accepted rule was invoked with messageType "
        f"{_annotation_field(annotation, 'msgType')!r}, expected "
        f"ConfigurationItemChangeNotification -- the control has to exercise the PUSH path, not a "
        f"scheduled sweep"
    )
    assert _annotation_field(annotation, "observed") == _INITIAL_TIMEOUT, (
        f"the evaluator read VisibilityTimeout {_annotation_field(annotation, 'observed')!r} out "
        f"of the configurationItem Config handed it, expected {_INITIAL_TIMEOUT!r}"
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
