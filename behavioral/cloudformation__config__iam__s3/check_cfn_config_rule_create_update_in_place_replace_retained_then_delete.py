"""cfn-config-rule-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-config-rule-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "config", "iam", "s3"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A custom rule's evaluation lands within a minute or two; the bound only stops a hung poll.
_EVALUATION_S = 180.0
#: StartConfigRulesEvaluation runs at most once a minute; a restart waits a little longer.
_RESTART_S = 65.0
#: A rule reads EVALUATING while an evaluation runs, then ACTIVE; the bound stops a hung poll.
_ACTIVE_S = 60.0
#: A deleted rule leaves DescribeConfigRules once its deletion ends; the bound stops a hung poll.
_GONE_S = 120.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: DescribeConfigRules of a rule that does not exist.
_NOT_FOUND = (
    "NoSuchConfigRuleException",
    "One or more ConfigRules provided in the request are invalid. "
    "Please check the configRule names.",
)
#: DeleteConfigRule of a rule that does not exist; formatted with the rule name.
_DELETE_RULE_GONE = (
    "NoSuchConfigRuleException",
    "The ConfigRule '{name}' provided in the request is invalid. Please check the configRule name.",
)
#: DetachRolePolicy of a policy the role does not have attached; formatted with the policy ARN.
_DETACHED = ("NoSuchEntity", "Policy {arn} was not found.")
#: ListObjectsV2 or DeleteBucket of a bucket that does not exist.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")
#: DeleteConfigurationRecorder of a recorder name that does not exist.
_NO_RECORDER = (
    "NoSuchConfigurationRecorderException",
    "The name of the configuration recorder you entered cannot be found. "
    "Verify the configuration recorder name, and try again.",
)
#: GetRole of a role that does not exist; formatted with the role name.
_NO_ROLE = ("NoSuchEntity", "The role with name {name} cannot be found.")
#: DeleteDeliveryChannel of a channel that does not exist; formatted with the channel name.
_NO_CHANNEL = (
    "NoSuchDeliveryChannelException",
    "Cannot find delivery channel with specified name '{name}'.",
)
#: The rule's function writes one evaluation for the account, annotated with the rule parameter.
_LAMBDA_CODE = (
    "import datetime\n"
    "import json\n\n"
    "import boto3\n\n\n"
    "def handler(event, context):\n"
    "    params = json.loads(event.get('ruleParameters') or '{}')\n"
    "    boto3.client('config').put_evaluations(\n"
    "        Evaluations=[{\n"
    "            'ComplianceResourceType': 'AWS::::Account',\n"
    "            'ComplianceResourceId': event['accountId'],\n"
    "            'ComplianceType': 'NON_COMPLIANT',\n"
    "            'Annotation': params['annotation'],\n"
    "            'OrderingTimestamp': datetime.datetime.now(datetime.UTC),\n"
    "        }],\n"
    "        ResultToken=event['resultToken'],\n"
    "    )\n"
    "    return 'done'\n"
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
    "resource:account-singleton:config-delivery-channel",
    "resource:account-singleton:config-recorder",
)
def run(ctx) -> None:
    """An AWS::Config::ConfigRule survives create, in-place update, retained replacement and delete.

    Config reads back the rule and its evaluations carry the InputParameters annotation; changing
    both keeps the rule and re-annotates; a ConfigRuleName change under Retain keeps the old rule.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-configrule.html
    """
    found = _restore_config_recorder_on_teardown(ctx)
    _ensure_configuration_recorder(ctx, found)
    cfn = ctx.client("cloudformation")
    config = ctx.client("config")

    stack_name = ctx.unique_name("sim2real-cfnreal-config-")
    rule_v1 = ctx.unique_name("sim2real-cfnreal-rule-a-")
    rule_v2 = ctx.unique_name("sim2real-cfnreal-rule-b-")
    first = ("sim2real config rule, first", "first-annotation")
    updated = ("sim2real config rule, updated", "updated-annotation")

    # The replaced rule outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_rule(config, rule_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, Config view, behaviour -----------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(rule_v1, *first),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Rule", rule_v1)
    outputs = _outputs(cfn, stack_id)
    rule = _assert_rule(ctx, config, rule_v1, *first, outputs["FunctionArn"])
    assert (outputs["Arn"], outputs["RuleId"]) == (
        rule["ConfigRuleArn"],
        rule["ConfigRuleId"],
    ), f"GetAtt Arn and ConfigRuleId must be Config's: {outputs!r} vs {rule!r}"
    rule_id = rule["ConfigRuleId"]
    # Config evaluates a new rule by itself, so the first evaluation is awaited, not started.
    _evaluated(ctx, config, rule_v1, ctx.account, first[1], start=False)

    # ---- 2. in-place update of the mutable Description and InputParameters ------------------
    rows = _update(
        ctx,
        cfn,
        stack_id,
        "Rule",
        _template(rule_v1, *updated),
        Capabilities=["CAPABILITY_IAM"],
    )
    _assert_updated_in_place(rows, rule_v1)
    _assert_tracks(cfn, stack_id, "Rule", rule_v1)
    rule = _assert_rule(ctx, config, rule_v1, *updated, outputs["FunctionArn"])
    assert rule["ConfigRuleId"] == rule_id, f"an in-place update keeps the rule {rule_id!r}"
    # Behaviour: the next evaluation passes the updated InputParameters to the function.
    _evaluated(ctx, config, rule_v1, ctx.account, updated[1], start=True)

    # ---- 3. ConfigRuleName forces replacement; UpdateReplacePolicy Retain keeps the old -----
    rows = _update(
        ctx,
        cfn,
        stack_id,
        "Rule",
        _template(rule_v2, *updated),
        Capabilities=["CAPABILITY_IAM"],
    )
    _assert_replaced_and_retained(rows, rule_v1, rule_v2)
    _assert_tracks(cfn, stack_id, "Rule", rule_v2)
    new = _assert_rule(ctx, config, rule_v2, *updated, outputs["FunctionArn"])
    assert new["ConfigRuleId"] != rule_id, f"the replacement is a new rule, got {rule_id!r}"
    old = _assert_rule(ctx, config, rule_v1, *updated, outputs["FunctionArn"])
    assert old["ConfigRuleId"] == rule_id, f"the retained rule keeps its id {rule_id!r}: {old!r}"

    # ---- 4. DeleteStack: the rule it owns is gone, the retained one stays -------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    got = _poll(
        ctx,
        lambda: _refusal(lambda: config.describe_config_rules(ConfigRuleNames=[rule_v2])),
        lambda e: e[0] != "<exists>",
        cap_s=_GONE_S,
        what=f"DescribeConfigRules of {rule_v2!r} refused after DeleteStack",
    )
    assert got == _NOT_FOUND, f"DescribeConfigRules after DeleteStack: {got!r}, not {_NOT_FOUND!r}"
    kept = config.describe_config_rules(ConfigRuleNames=[rule_v1])["ConfigRules"]
    assert [r["ConfigRuleId"] for r in kept] == [rule_id], (
        f"the retained rule {rule_v1!r} must survive DeleteStack: {kept!r}"
    )


def _template(name: str, description: str, annotation: str) -> str:
    put_evaluations = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "config:PutEvaluations", "Resource": "*"}],
    }
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "EvalRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": trust,
                        "Policies": [
                            {
                                "PolicyName": "put-evaluations",
                                "PolicyDocument": put_evaluations,
                            }
                        ],
                    },
                },
                "EvalFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["EvalRole", "Arn"]},
                        "Timeout": 30,
                        "Code": {"ZipFile": _LAMBDA_CODE},
                    },
                },
                "InvokePermission": {
                    "Type": "AWS::Lambda::Permission",
                    "Properties": {
                        "FunctionName": {"Ref": "EvalFunction"},
                        "Action": "lambda:InvokeFunction",
                        "Principal": "config.amazonaws.com",
                        "SourceAccount": {"Ref": "AWS::AccountId"},
                    },
                },
                "Rule": {
                    "Type": "AWS::Config::ConfigRule",
                    "DependsOn": "InvokePermission",
                    # ConfigRuleName is create-only, so a new name replaces the rule.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ConfigRuleName": name,
                        "Description": description,
                        "InputParameters": {"annotation": annotation},
                        "MaximumExecutionFrequency": "TwentyFour_Hours",
                        "Source": {
                            "Owner": "CUSTOM_LAMBDA",
                            "SourceIdentifier": {"Fn::GetAtt": ["EvalFunction", "Arn"]},
                            "SourceDetails": [
                                {
                                    "EventSource": "aws.config",
                                    "MessageType": "ScheduledNotification",
                                    "MaximumExecutionFrequency": "TwentyFour_Hours",
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "Arn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}},
                "RuleId": {"Value": {"Fn::GetAtt": ["Rule", "ConfigRuleId"]}},
                "FunctionArn": {"Value": {"Fn::GetAtt": ["EvalFunction", "Arn"]}},
            },
        }
    )


def _outputs(cfn, stack_id: str) -> dict:
    stack = _stack(cfn, stack_id)
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _assert_rule(
    ctx, config, name: str, description: str, annotation: str, function_arn: str
) -> dict:
    """Config's view: once no evaluation runs, the one rule named name carries the template."""
    rules = _poll(
        ctx,
        lambda: config.describe_config_rules(ConfigRuleNames=[name])["ConfigRules"],
        lambda rs: [r.get("ConfigRuleState") for r in rs] == ["ACTIVE"],
        cap_s=_ACTIVE_S,
        what=f"rule {name!r} ACTIVE",
    )
    assert len(rules) == 1, f"Config must hold exactly one rule {name!r}, got {rules!r}"
    rule = rules[0]
    got = (
        rule["ConfigRuleName"],
        rule.get("Description"),
        json.loads(rule.get("InputParameters") or "null"),
        rule.get("MaximumExecutionFrequency"),
        rule["Source"]["Owner"],
        rule["Source"].get("SourceIdentifier"),
        rule.get("ConfigRuleState"),
    )
    want = (
        name,
        description,
        {"annotation": annotation},
        "TwentyFour_Hours",
        "CUSTOM_LAMBDA",
        function_arn,
        "ACTIVE",
    )
    assert got == want, f"DescribeConfigRules {name!r} must report {want!r}, got {got!r}"
    return rule


def _evaluated(ctx, config, rule_name: str, account_id: str, annotation: str, *, start: bool):
    """Behaviour: the account's evaluation result once it carries annotation, NON_COMPLIANT.

    With start, the first probe starts an evaluation; any later start waits _RESTART_S, since a
    run that reaches the function before its role's permissions propagate records nothing.
    """
    started = [float("-inf") if start else time.monotonic()]

    def probe():
        if time.monotonic() - started[0] >= _RESTART_S:
            _start_evaluation(config, rule_name)
            started[0] = time.monotonic()
        results = config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)
        return [
            r
            for r in results.get("EvaluationResults", [])
            if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"].get("ResourceId")
            == account_id
        ]

    found = _poll(
        ctx,
        probe,
        lambda rs: [r.get("Annotation") for r in rs] == [annotation],
        cap_s=_EVALUATION_S,
        what=f"an evaluation of account {account_id} by {rule_name!r} annotated {annotation!r}",
    )
    assert found[0]["ComplianceType"] == "NON_COMPLIANT", (
        f"the function reports NON_COMPLIANT, Config recorded {found[0]!r}"
    )
    return found[0]


def _start_evaluation(config, rule_name: str) -> None:
    """StartConfigRulesEvaluation; an evaluation already running (either code) is left running."""
    try:
        config.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "LimitExceededException",
            "ResourceInUseException",
        ):
            raise


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises, or an <exists> pair while it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    return "<exists>", "the call still succeeds"


def _delete_rule(config, name: str) -> None:
    """Teardown: delete the rule, waiting out an evaluation still in progress on it."""
    _safe(
        lambda: config.delete_config_rule(ConfigRuleName=name),
        (_DELETE_RULE_GONE[0], _DELETE_RULE_GONE[1].format(name=name)),
        busy=("ResourceInUseException",),
    )


# ===== account singletons: the Config recorder and delivery channel =====


def _safe(fn, *gone, busy=()) -> None:
    """Teardown call: return on a gone (code, message) pair, retry busy codes, raise others.

    A busy code retries every 2 s for up to 120 s, then raises.
    """
    deadline = time.monotonic() + 120
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if (code, exc.response["Error"].get("Message")) in gone:
                return
            if code not in busy or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _confirmed_gone(fn, lookup, gone: tuple[str, str]) -> None:
    """Teardown call: a refused fn passes only once lookup raises the exact gone pair."""
    try:
        fn()
    except ClientError as exc:
        try:
            lookup()
        except ClientError as missing:
            err = missing.response["Error"]
            if (err["Code"], err.get("Message")) == gone:
                return
            raise exc from missing
        raise


def _empty_and_delete_bucket(s3, bucket) -> None:
    """Config writes into its delivery bucket, so remove the objects before the bucket."""
    for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _retry(fn, retry_codes: set[str], attempts: int = 20, delay: float = 2.0):
    """Call fn, retrying retry_codes every delay seconds; the last attempt's error is raised."""
    for _ in range(attempts - 1):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in retry_codes:
                raise
        time.sleep(delay)
    return fn()


def _ensure_configuration_recorder(ctx, found: dict) -> None:
    """A rule needs a recording customer recorder with a delivery channel; add what is missing.

    *found* is the account's state read before the check changed anything, the same state the
    teardown restores. A periodic custom rule evaluates through the recorded path: a recorder,
    a delivery channel and a started recorder, so each one the account lacks is added here.
    """
    config = ctx.client("config")
    if found["recorders"]:
        recorder = found["recorders"][0]
        recorder_name = recorder["name"]
        partition = recorder["roleARN"].split(":")[1]
    else:
        recorder_name, partition = _add_recorder(ctx, config)
    if not found["channels"]:
        _add_delivery_channel(ctx, config, partition)
    if recorder_name in found["recording"]:
        return
    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(
        lambda: _confirmed_gone(
            lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name),
            lambda: config.describe_configuration_recorders(
                ConfigurationRecorderNames=[recorder_name]
            ),
            _NO_RECORDER,
        )
    )


def _add_recorder(ctx, config) -> tuple[str, str]:
    """Create a customer recorder with its own role; return its name and the role's partition."""
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "config-recorder-role"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(
        lambda: _confirmed_gone(
            lambda: iam.delete_role(RoleName=role_name),
            lambda: iam.get_role(RoleName=role_name),
            (_NO_ROLE[0], _NO_ROLE[1].format(name=role_name)),
        )
    )
    partition = role_arn.split(":")[1]
    policy_arn = f"arn:{partition}:iam::aws:policy/service-role/AWS_ConfigRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            (_DETACHED[0], _DETACHED[1].format(arn=policy_arn)),
        )
    )

    recorder_name = ctx.unique_name("sim2real-recorder-")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": recorder_name,
            "roleARN": role_arn,
            "recordingGroup": {
                "allSupported": True,
                "includeGlobalResourceTypes": False,
            },
        }
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name),
            _NO_RECORDER,
        )
    )

    return recorder_name, partition


def _add_delivery_channel(ctx, config, partition: str) -> None:
    """Create a delivery bucket Config may write to, and a delivery channel into it."""
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-config-bucket-").lower()
    region = ctx.region
    # S3 refuses a LocationConstraint naming us-east-1, its default Region.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: _empty_and_delete_bucket(s3, bucket_name),
            _NO_SUCH_BUCKET,
            busy=("BucketNotEmpty",),
        )
    )
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "config-delivery-bucket"}]},
    )

    account_id = ctx.account
    bucket_arn = f"arn:{partition}:s3:::{bucket_name}"
    source = {"StringEquals": {"AWS:SourceAccount": account_id}}
    principal = {"Service": "config.amazonaws.com"}
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSConfigBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": principal,
                "Action": "s3:GetBucketAcl",
                "Resource": bucket_arn,
                "Condition": source,
            },
            {
                "Sid": "AWSConfigBucketExistenceCheck",
                "Effect": "Allow",
                "Principal": principal,
                "Action": "s3:ListBucket",
                "Resource": bucket_arn,
                "Condition": source,
            },
            {
                "Sid": "AWSConfigBucketDelivery",
                "Effect": "Allow",
                "Principal": principal,
                "Action": "s3:PutObject",
                "Resource": f"{bucket_arn}/AWSLogs/{account_id}/Config/*",
                "Condition": source,
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    channel_name = ctx.unique_name("sim2real-channel-")
    _retry(
        lambda: config.put_delivery_channel(
            DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}
        ),
        retry_codes={"InsufficientDeliveryPolicyException"},
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name),
            (_NO_CHANNEL[0], _NO_CHANNEL[1].format(name=channel_name)),
        )
    )


def _restore_config_recorder_on_teardown(ctx) -> dict:
    """Read the account's Config recorders and delivery channels now; restore exactly those last.

    They exist once per account and Region; the restore runs after the check's own teardowns.
    Returns what was read: the customer ``recorders``, the names ``recording`` and ``channels``.
    """
    cfg = ctx.client("config")

    def _call(fn):
        deadline = time.monotonic() + 60.0
        while True:
            try:
                return fn()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code != "ThrottlingException" or time.monotonic() > deadline:
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
                _call(
                    lambda n=r["name"]: cfg.delete_configuration_recorder(
                        ConfigurationRecorderName=n
                    )
                )
        for r in recorders:
            body = {k: v for k, v in r.items() if k in fields}
            _call(lambda b=body: cfg.put_configuration_recorder(ConfigurationRecorder=b))
        for c in channels:
            _call(lambda c=c: cfg.put_delivery_channel(DeliveryChannel=c))
        for r in recorders:
            if r["name"] in recording:
                _call(
                    lambda n=r["name"]: cfg.start_configuration_recorder(
                        ConfigurationRecorderName=n
                    )
                )

    ctx.on_cleanup(_restore)
    return {"recorders": recorders, "recording": recording, "channels": channels}


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
