"""put-config-rule-custom-lambda-full-field-round-trip."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

_LAMBDA_BASIC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

# The evaluator is never invoked here; PutConfigRule only probes that the function is invokable
# (InsufficientPermissionsException otherwise), so a no-op handler lets the rule reach ACTIVE.
_HANDLER_SOURCE = """
def handler(event, context):
    return "sim2real-noop"
"""

CHECK = "put-config-rule-custom-lambda-full-field-round-trip"
GROUP = "config-rule"
SERVICES = ["config"]


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


def _ensure_recorder_exists(ctx):
    """Guarantee a configuration recorder EXISTS without touching one we did not create;
    never start one (account-wide, billed per configuration item)."""
    cfg = ctx.client("config")
    existing = _retry_throttled(cfg.describe_configuration_recorders).get(
        "ConfigurationRecorders", []
    )
    if existing:
        return

    role_arn = _config_slr_arn(ctx)

    recorder = ctx.unique_name("sim2real-behav-cfg-lrecorder-")
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder,
                        "roleARN": role_arn,
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
            time.sleep(5)
    else:
        raise AssertionError(f"could not create a configuration recorder within 120s: {last!r}")
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder)
        )
    )


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """DescribeConfigRules returns every field of a CUSTOM_LAMBDA rule verbatim (Description, Scope,
    Source, InputParameters, MaximumExecutionFrequency, default EvaluationModes), with a minted
    ConfigRuleArn/ConfigRuleId and ConfigRuleState ACTIVE.
    """
    cfg = ctx.client("config")
    iam = ctx.client("iam")
    _ensure_recorder_exists(ctx)

    fn_role = ctx.unique_name("sim2real-behav-cfg-rtfn-")
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
        Description="sim2real behavioral fidelity probe role for a CUSTOM_LAMBDA Config rule",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fn_role))
    iam.attach_role_policy(RoleName=fn_role, PolicyArn=_LAMBDA_BASIC_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=fn_role, PolicyArn=_LAMBDA_BASIC_POLICY_ARN)
    )

    lam = ctx.client("lambda")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _HANDLER_SOURCE)
    fn_name = ctx.unique_name("sim2real-behav-cfg-rtfn-")
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
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            time.sleep(5.0)
    assert fn_arn, f"CreateFunction never succeeded: {last!r}"
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
        lambda s: s == "Active",
        timeout_s=180,
        interval_s=4.0,
        description=f"function {fn_name!r} reaches Active",
    )
    assert state == "Active", state

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-behav-config-invoke",
        Action="lambda:InvokeFunction",
        Principal="config.amazonaws.com",
        SourceAccount=account_id,
    )

    rule_name = ctx.unique_name("sim2real-behav-cfg-rt-rule-")
    input_parameters = json.dumps({"maxPolicySize": 5})
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            cfg.put_config_rule(
                ConfigRule={
                    "ConfigRuleName": rule_name,
                    "Description": "Checks bucket policies",
                    # A Scope naming both ComplianceResourceTypes and TagKey is refused with
                    # InvalidParameterValueException.
                    "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
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
                    "InputParameters": input_parameters,
                    "MaximumExecutionFrequency": "Six_Hours",
                }
            )
            break
        except ClientError as exc:
            last = exc
            # The function's own invoke permission can still be propagating even after
            # add_permission above returned; Config re-probes invokability at PutConfigRule
            # time and reports that specific, transient window as InsufficientPermissionsException.
            if exc.response.get("Error", {}).get("Code") != "InsufficientPermissionsException":
                raise
            time.sleep(5.0)
    else:
        raise AssertionError(f"PutConfigRule never accepted the CUSTOM_LAMBDA source: {last!r}")
    ctx.on_cleanup(
        lambda: _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))
    )

    described = _poll_until(
        lambda: _retry_throttled(
            lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name])
        )["ConfigRules"][0],
        lambda r: r.get("ConfigRuleState") == "ACTIVE",
        timeout_s=60,
        interval_s=3.0,
        description=f"rule {rule_name!r} reaches ACTIVE",
    )

    assert described["ConfigRuleName"] == rule_name, described
    assert described["ConfigRuleArn"].startswith("arn:aws:config:"), described["ConfigRuleArn"]
    assert described["ConfigRuleId"], described
    assert described["ConfigRuleState"] == "ACTIVE", described
    assert described["Description"] == "Checks bucket policies", described["Description"]
    assert described["Scope"]["ComplianceResourceTypes"] == ["AWS::S3::Bucket"], described["Scope"]
    assert "TagKey" not in described["Scope"], described["Scope"]
    assert described["Source"]["Owner"] == "CUSTOM_LAMBDA", described["Source"]
    assert described["Source"]["SourceIdentifier"] == fn_arn, described["Source"]
    assert described["Source"]["SourceDetails"] == [
        {"EventSource": "aws.config", "MessageType": "ConfigurationItemChangeNotification"}
    ], described["Source"]["SourceDetails"]
    assert described["InputParameters"] == input_parameters, described["InputParameters"]
    assert described["MaximumExecutionFrequency"] == "Six_Hours", (
        described["MaximumExecutionFrequency"]
    )
    assert described["EvaluationModes"] == [{"Mode": "DETECTIVE"}], described["EvaluationModes"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
