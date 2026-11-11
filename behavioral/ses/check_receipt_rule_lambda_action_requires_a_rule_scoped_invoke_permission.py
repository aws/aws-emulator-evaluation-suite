"""receipt-rule-lambda-action-requires-a-rule-scoped-invoke-permission."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-lambda-action-requires-a-rule-scoped-invoke-permission"
GROUP = "overly-permissive"
SERVICES = ["ses"]

# SES email receiving exists only in some regions, and the Lambda function must share the SES
# endpoint's region, so both clients are pinned to a receiving region.
# https://docs.aws.amazon.com/general/latest/gr/ses.html#ses_inbound_endpoints
_RECEIVING_REGIONS = ("us-east-1", "us-west-2", "eu-west-1")
_DEFAULT_RECEIVING_REGION = "us-east-1"
_RUNTIME = "python3.12"
_HANDLER_SOURCE = "def handler(event, context):\n    return {'ok': True}\n"


def _client_error(fn) -> dict:
    """Return the botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_call(fn, *, timeout_s, interval_s, description):
    """Call fn() until it stops raising ClientError; RAISE on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            last = exc.response.get("Error", {})
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not succeed within {timeout_s}s; last refusal {last!r}"
            )
        time.sleep(interval_s)


def _zip_handler() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("handler.py", _HANDLER_SOURCE)
    return buffer.getvalue()


def _receipt_rule_arn(region: str, account: str, rule_set: str, rule: str) -> str:
    """The SourceArn shape the SES Developer Guide publishes for the Lambda invoke grant.
    https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html"""
    return (
        f"arn:aws:ses:{region}:{account}:receipt-rule-set/{rule_set}"
        f":receipt-rule/{rule}"
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A LambdaAction rule is refused with InvalidLambdaFunction unless the function's resource
    policy grants ses.amazonaws.com with a SourceArn naming THIS rule; the scoped grant makes the
    identical call succeed, and SES adds no statements to the function's policy itself.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    recv_region = (
        ctx.region if ctx.region in _RECEIVING_REGIONS else _DEFAULT_RECEIVING_REGION
    )
    ses = ctx.client("ses", region=recv_region)
    lam = ctx.client("lambda", region=recv_region)
    iam = ctx.client("iam")

    # Nothing asserts on the execution role; Lambda requires one.
    role_name = ctx.unique_name("sim2real-behav-ses-lambda-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    function_name = ctx.unique_name("sim2real-behav-ses-inbound-fn-")
    created = _poll_call(
        lambda: lam.create_function(
            FunctionName=function_name,
            Runtime=_RUNTIME,
            Role=role_arn,
            Handler="handler.handler",
            Code={"ZipFile": _zip_handler()},
            Timeout=10,
            Tags={"sim2real": CHECK},
        ),
        timeout_s=120,
        interval_s=5,
        description="Lambda accepts the freshly created execution role (IAM role propagation)",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    function_arn = created["FunctionArn"]
    # The function must be observably real, so the refusals below are not "no such function".
    assert (
        lam.get_function_configuration(FunctionName=function_name)["FunctionArn"]
        == function_arn
    ), f"setup precondition: the function {function_name!r} must be readable back"
    no_policy = _client_error(lambda: lam.get_policy(FunctionName=function_name))
    assert (no_policy.get("Code"), no_policy.get("Message")) == (
        "ResourceNotFoundException",
        "The resource you requested does not exist.",
    ), (
        f"setup precondition: the fresh function must carry NO resource policy, so the only thing "
        f"broken in the negative legs is the grant; GetPolicy answered {no_policy!r}"
    )

    rule_set = ctx.unique_name("sim2real-behav-ses-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))

    # Control: rule creation in this rule set works at all.
    control_rule = "control-add-header"
    ses.create_receipt_rule(
        RuleSetName=rule_set,
        Rule={
            "Name": control_rule,
            "Enabled": True,
            "ScanEnabled": False,
            "Actions": [
                {"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": CHECK}}
            ],
        },
    )
    assert control_rule in [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ], "positive control: an AddHeaderAction rule must be creatable in this rule set"

    lambda_rule = "lambda-invoke"

    def _create_lambda_rule():
        return ses.create_receipt_rule(
            RuleSetName=rule_set,
            Rule={
                "Name": lambda_rule,
                "Enabled": True,
                "ScanEnabled": False,
                "Actions": [
                    {
                        "LambdaAction": {
                            "FunctionArn": function_arn,
                            "InvocationType": "Event",
                        }
                    }
                ],
            },
        )

    # The function is real and in the right region; only the invoke permission is missing.
    cannot_invoke = ("InvalidLambdaFunction", f"Could not invoke Lambda function: {function_arn}")
    no_grant = _client_error(_create_lambda_rule)
    assert (no_grant.get("Code"), no_grant.get("Message")) == cannot_invoke, (
        f"a LambdaAction naming an EXISTING function that grants ses.amazonaws.com nothing must be "
        f"refused with InvalidLambdaFunction; got {no_grant.get('Code')!r}: "
        f"{no_grant.get('Message')!r}"
    )

    # A grant that exists but is scoped to the WRONG receipt rule.
    wrong_rule = "some-other-rule"
    assert wrong_rule != lambda_rule, "the mis-scoped SourceArn must name a different rule"
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-ses-wrong-scope",
        Action="lambda:InvokeFunction",
        Principal="ses.amazonaws.com",
        SourceAccount=account,
        SourceArn=_receipt_rule_arn(recv_region, account, rule_set, wrong_rule),
    )
    stored_wrong = json.loads(lam.get_policy(FunctionName=function_name)["Policy"])
    wrong_sids = sorted(s["Sid"] for s in stored_wrong["Statement"])
    assert wrong_sids == ["sim2real-ses-wrong-scope"], (
        f"the mis-scoped grant must be observably stored before anything is concluded from its "
        f"effect; GetPolicy reported statement ids {wrong_sids!r}"
    )
    mis_scoped = _client_error(_create_lambda_rule)
    assert (mis_scoped.get("Code"), mis_scoped.get("Message")) == cannot_invoke, (
        f"a lambda:InvokeFunction grant whose SourceArn names receipt rule {wrong_rule!r} must not "
        f"authorize a rule named {lambda_rule!r}; expected InvalidLambdaFunction, got "
        f"{mis_scoped.get('Code')!r}: {mis_scoped.get('Message')!r}"
    )

    rules_after_refusals = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ]
    assert rules_after_refusals == [control_rule], (
        f"neither refused CreateReceiptRule may persist a rule; DescribeReceiptRuleSet lists "
        f"{rules_after_refusals!r}"
    )

    # Added alongside the mis-scoped grant, so the only change is a statement matching this rule.
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-ses-right-scope",
        Action="lambda:InvokeFunction",
        Principal="ses.amazonaws.com",
        SourceAccount=account,
        SourceArn=_receipt_rule_arn(recv_region, account, rule_set, lambda_rule),
    )

    # A new invoke permission takes time to become effective for SES's pre-flight.
    _poll_call(
        _create_lambda_rule,
        timeout_s=180,
        interval_s=10,
        description="CreateReceiptRule accepts the LambdaAction once a grant scoped to THIS rule "
        "exists",
    )

    described = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=lambda_rule)["Rule"]
    actions = described["Actions"]
    assert len(actions) == 1, f"expected exactly one action on {lambda_rule!r}, got {actions!r}"
    assert actions[0]["LambdaAction"]["FunctionArn"] == function_arn, (
        f"DescribeReceiptRule must report the granted function {function_arn!r}, got "
        f"{actions[0]!r}"
    )
    final_policy = json.loads(lam.get_policy(FunctionName=function_name)["Policy"])
    final_sids = sorted(s["Sid"] for s in final_policy["Statement"])
    assert final_sids == ["sim2real-ses-right-scope", "sim2real-ses-wrong-scope"], (
        f"SES must not add statements to the function's resource policy itself — the API path is "
        f"documented as leaving that to the caller; GetPolicy reported {final_sids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
