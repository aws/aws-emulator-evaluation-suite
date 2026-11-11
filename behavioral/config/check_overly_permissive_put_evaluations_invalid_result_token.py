"""overly-permissive-put-evaluations-invalid-result-token."""

from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====

_LAMBDA_BASIC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_POSITIVE_ANNOTATION = "sim2real-behav-cfg-positive-control"

# The positive-control evaluator: Config invokes it with a genuine resultToken, which it spends
# on PutEvaluations.
_HANDLER_SOURCE = """
import datetime
import boto3


def handler(event, context):
    cfg = boto3.client("config")
    cfg.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": "AWS::::Account",
            "ComplianceResourceId": event["accountId"],
            "ComplianceType": "COMPLIANT",
            "Annotation": "sim2real-behav-cfg-positive-control",
            "OrderingTimestamp": datetime.datetime.utcnow(),
        }],
        ResultToken=event["resultToken"],
    )
    return "done"
"""


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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


def _ensure_recorder_exists(ctx):
    """Guarantee a configuration recorder EXISTS without touching one we did not
    create; never start one (account-wide, billed per configuration item)."""
    cfg = ctx.client("config")
    existing = _retry_throttled(cfg.describe_configuration_recorders).get(
        "ConfigurationRecorders", []
    )
    if existing:
        return existing[0]["name"], False

    role_arn = _config_slr_arn(ctx)

    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder,
                        "roleARN": role_arn,
                        # allSupported=False with an empty resourceTypes list is refused with
                        # InvalidRecordingGroupException; one narrow type keeps the recorder cheap.
                        "recordingGroup": {
                            "allSupported": False,
                            "resourceTypes": ["AWS::S3::Bucket"],
                        },
                    }
                )
            )
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code", "") not in (
                "InsufficientPermissionsException",
                "InvalidRoleException",
                "ValidationException",
            ):
                raise
            time.sleep(2)
    else:
        raise AssertionError(f"could not create a configuration recorder within 120s: {last!r}")
    ctx.on_cleanup(
        lambda r=recorder: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=r)
        )
    )
    return recorder, True


def _must_reject(fn, description):
    """Return (code, message) of fn()'s ClientError; raises if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"{description}: the call succeeded instead of being rejected")


CHECK = "overly-permissive-put-evaluations-invalid-result-token"
GROUP = "overly-permissive"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutEvaluations with a forged ResultToken is rejected with InvalidResultTokenException and
    records nothing, while a CUSTOM_LAMBDA rule's genuine token is accepted as a positive control.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    account_id = sts.get_caller_identity()["Account"]
    _ensure_recorder_exists(ctx)

    # --- Positive control: a genuine CUSTOM_LAMBDA rule accepts a REAL ResultToken.
    fn_role = ctx.unique_name("sim2real-behav-cfg-putevalfn-")
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
        Description="sim2real behavioral fidelity probe role for Config PutEvaluations",
        Tags=[{"Key": "sim2real", "Value": "config-put-evaluations-positive-control"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fn_role))
    iam.attach_role_policy(RoleName=fn_role, PolicyArn=_LAMBDA_BASIC_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=fn_role, PolicyArn=_LAMBDA_BASIC_POLICY_ARN)
    )
    iam.put_role_policy(
        RoleName=fn_role,
        PolicyName="sim2real-put-evaluations",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["config:PutEvaluations"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=fn_role, PolicyName="sim2real-put-evaluations")
    )

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _HANDLER_SOURCE)
    fn_name = ctx.unique_name("sim2real-behav-cfg-putevalfn-")
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
                Timeout=30,
                Tags={"sim2real": "config-put-evaluations-positive-control"},
            )["FunctionArn"]
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            time.sleep(2.0)
    assert fn_arn, f"CreateFunction never succeeded: {last!r}"
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s == "Active",
        timeout_s=180,
        interval_s=1.0,
        description=f"function {fn_name!r} reaches Active",
        ctx=ctx,
    )
    assert state == "Active", state

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-behav-config-invoke",
        Action="lambda:InvokeFunction",
        Principal="config.amazonaws.com",
        SourceAccount=account_id,
    )

    rule_name = ctx.unique_name("sim2real-behav-cfg-putevalrule-")
    _retry_throttled(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Source": {
                    "Owner": "CUSTOM_LAMBDA",
                    "SourceIdentifier": fn_arn,
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            "MessageType": "ScheduledNotification",
                            "MaximumExecutionFrequency": "TwentyFour_Hours",
                        }
                    ],
                },
            }
        )
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))
    )

    _poll_until(
        lambda: _retry_throttled(lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name]))[
            "ConfigRules"
        ][0],
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        timeout_s=60,
        interval_s=1.0,
        description=f"rule {rule_name!r} reaches ACTIVE",
        ctx=ctx,
    )

    for attempt in range(30):
        try:
            cfg.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
            break
        except cfg.exceptions.ResourceInUseException:
            time.sleep(1)
    else:
        raise AssertionError("could not start config rule evaluation (rule stayed busy)")

    positive = _poll_until(
        lambda: [
            r
            for r in _retry_throttled(
                lambda: cfg.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)
            ).get("EvaluationResults", [])
            if r.get("Annotation") == _POSITIVE_ANNOTATION
        ],
        lambda results: bool(results),
        timeout_s=180,
        interval_s=1.0,
        description=f"a genuine ResultToken is accepted for rule {rule_name!r}",
        ctx=ctx,
    )
    assert positive[0]["ComplianceType"] == "COMPLIANT", (
        f"the positive control's own genuine ResultToken was accepted but recorded "
        f"{positive[0]['ComplianceType']!r} instead of COMPLIANT: {positive[0]!r}"
    )

    # --- The negative: a malformed/unknown ResultToken, on the SAME operation the
    # positive control just proved works, must be refused with the specific code.
    code, message = _must_reject(
        lambda: cfg.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType": "AWS::S3::Bucket",
                    "ComplianceResourceId": "does-not-matter",
                    "ComplianceType": "COMPLIANT",
                    "OrderingTimestamp": datetime.now(timezone.utc),
                }
            ],
            ResultToken="not-a-real-result-token",
        ),
        "PutEvaluations with a malformed ResultToken",
    )
    assert code == "InvalidResultTokenException", (
        f"expected InvalidResultTokenException for a malformed ResultToken, got "
        f"{code!r} (message {message!r})"
    )
    assert message == "Result Token provided is invalid", message

    # --- Effect absent: the rejected call must have fabricated no compliance verdict
    # for the resource it targeted. Independent read, different operation.
    by_resource = _retry_throttled(
        lambda: cfg.get_compliance_details_by_resource(
            ResourceType="AWS::S3::Bucket", ResourceId="does-not-matter"
        )
    ).get("EvaluationResults", [])
    assert by_resource == [], (
        f"a rejected PutEvaluations call must record no compliance verdict for the "
        f"resource it targeted; found {by_resource!r}"
    )

    # --- Terminal read at the destination: the genuine rule is still intact after the
    # forged call, on an independent operation from every mutating call above.
    after = _retry_throttled(lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name]))[
        "ConfigRules"
    ][0]
    assert after["ConfigRuleState"] == "ACTIVE", (
        f"rule {rule_name!r} should still be ACTIVE after the forged-token call; got {after!r}"
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
