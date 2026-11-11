"""update-receipt-rule-invalid-lambda-function-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-receipt-rule-invalid-lambda-function-rejected"
GROUP = "error-semantics"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateReceiptRule with a LambdaAction on a nonexistent function fails with InvalidLambdaFunction
    and leaves the rule untouched, while a real function SES may invoke is accepted."""
    ses = ctx.client("ses")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    rule_set_name = ctx.unique_name("sim2real-ses-rs-")
    rule_name = ctx.unique_name("sim2real-ses-rule-")

    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))

    base_rule = {
        "Name": rule_name,
        "Enabled": True,
        "TlsPolicy": "Optional",
        "Recipients": [],
        "Actions": [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v1"}}],
        "ScanEnabled": False,
    }
    ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=base_rule)

    fn_name, fn_arn = _create_invokable_function(ctx, iam, lam)
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="ses-invoke",
        Action="lambda:InvokeFunction",
        Principal="ses.amazonaws.com",
        SourceAccount=account_id,
    )

    valid_rule = dict(base_rule)
    valid_rule["Actions"] = [
        {"LambdaAction": {"FunctionArn": fn_arn, "InvocationType": "Event"}}
    ]

    def _update_with_valid_lambda():
        ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=valid_rule)

    _retry_until_no_error(
        _update_with_valid_lambda,
        tolerate=("InvalidLambdaFunction",),
        timeout_s=30,
        description="SES accepting the real function after add_permission propagates",
    )

    described0 = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert described0["Actions"] == valid_rule["Actions"], (
        f"positive control: update with a real, invokable Lambda function did not take effect, "
        f"got {described0['Actions']!r}"
    )

    bogus_arn = (
        f"arn:aws:lambda:{ctx.region}:{account_id}:function:"
        f"{ctx.unique_name('sim2real-ses-nofn-')}"
    )
    bad_rule = dict(base_rule)
    bad_rule["Actions"] = [
        {"LambdaAction": {"FunctionArn": bogus_arn, "InvocationType": "Event"}}
    ]

    code = _error_code(
        lambda: ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=bad_rule)
    )
    assert code == ("InvalidLambdaFunction", f"Could not invoke Lambda function: {bogus_arn}"), (
        f"expected InvalidLambdaFunction, got {code!r}"
    )

    described = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert described["Actions"] == valid_rule["Actions"], (
        "rejected update mutated the stored rule's actions"
    )

    good_rule = dict(base_rule)
    good_rule["Actions"] = [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v2"}}]
    ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=good_rule)
    described2 = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert described2["Actions"][0]["AddHeaderAction"]["HeaderValue"] == "v2", (
        "restore update did not take effect"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_until_no_error(fn, *, tolerate: tuple[str, ...], timeout_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in tolerate:
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"timed out waiting for {description}: {last_exc}")


def _create_invokable_function(ctx, iam, lam) -> tuple[str, str]:
    """Create a real Lambda function for the positive-control LambdaAction; return (name, arn)."""
    role_name = ctx.unique_name("sim2real-ses-lambda-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]

    def _delete_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)

    fn_name = ctx.unique_name("sim2real-ses-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def lambda_handler(event, context):\n    return {'statusCode': 200}\n",
        )

    deadline = time.monotonic() + 40
    last_err = None
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_buf.getvalue()},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            fn_arn = resp["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
            break
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    if fn_arn is None:
        raise last_err or RuntimeError(f"failed to create lambda {fn_name}")

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if lam.get_function_configuration(FunctionName=fn_name).get("State") == "Active":
            break
        time.sleep(2)

    return fn_name, fn_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
