"""certificate-provider-singleton-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-provider-singleton-lifecycle"
GROUP = "state-machine"
SERVICES = ["iot"]


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control",
      "resource:account-singleton:iot-certificate-provider")
def run(ctx) -> None:
    """Only one certificate provider may hold the CreateCertificateFromCsr default: a second
    claim is rejected (InvalidRequestException) and succeeds once the first is deleted."""
    iot = ctx.client("iot")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    # CreateCertificateProvider invokes the Lambda to validate it, so a synthetic ARN is
    # rejected before default exclusivity can be observed.
    role_name = ctx.unique_name("sim2real-certprovider-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {}\n")
    fn_name = ctx.unique_name("sim2real-certprovider-fn-")

    def _create_fn():
        ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
        return lam.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=10,
        )

    # IAM role propagation for a new Lambda execution role can take a few
    # seconds; poll for success rather than sleeping a fixed duration.
    created_fn = _poll_until(lambda: _try(_create_fn), lambda r: r is not None, timeout_s=60.0, interval_s=3.0)
    assert created_fn is not None, "CreateFunction never succeeded (role propagation timeout)"
    ctx.on_cleanup(lambda: _safe_delete_fn(lam, fn_name))
    fn_arn = created_fn["FunctionArn"]

    active = _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert active == "Active", f"lambda function never became Active, last state={active}"

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="AllowIoTInvoke",
        Action="lambda:InvokeFunction",
        Principal="iot.amazonaws.com",
    )

    name = ctx.unique_name("sim2real-certprovider-")

    def _create_provider():
        return iot.create_certificate_provider(
            certificateProviderName=name,
            lambdaFunctionArn=fn_arn,
            accountDefaultForOperations=["CreateCertificateFromCsr"],
        )

    # IAM/Lambda permission propagation can also lag briefly.
    created = _poll_until(lambda: _try(_create_provider), lambda r: r is not None, timeout_s=60.0, interval_s=3.0)
    assert created is not None, "CreateCertificateProvider never succeeded (lambda permission propagation timeout)"
    ctx.on_cleanup(lambda: _safe_delete(iot, name))
    assert created["certificateProviderName"] == name, (
        f"expected create to echo {name!r}, got {created.get('certificateProviderName')!r}"
    )

    described = iot.describe_certificate_provider(certificateProviderName=name)
    assert described["lambdaFunctionArn"] == fn_arn, (
        f"expected describe to report lambdaFunctionArn={fn_arn!r}, got {described.get('lambdaFunctionArn')!r}"
    )
    assert described["accountDefaultForOperations"] == ["CreateCertificateFromCsr"], (
        "expected describe to report accountDefaultForOperations=['CreateCertificateFromCsr'], "
        f"got {described.get('accountDefaultForOperations')!r}"
    )

    second_name = ctx.unique_name("sim2real-certprovider2-")
    ctx.on_cleanup(lambda: _safe_delete(iot, second_name))
    code = _error_code(
        lambda: iot.create_certificate_provider(
            certificateProviderName=second_name,
            lambdaFunctionArn=fn_arn,
            accountDefaultForOperations=["CreateCertificateFromCsr"],
        )
    )
    # A second provider may exist; only the per-operation DEFAULT is exclusive, and the
    # refusal is InvalidRequestException, not LimitExceededException.
    assert code == ("InvalidRequestException", (
        f"Cannot set provider [{second_name}] as default for operation CreateCertificateFromCsr "
        "because another provider was set to be default for the operation"
    )), (
        f"expected InvalidRequestException for a second CreateCertificateFromCsr default, got {code!r}"
    )

    # Effect absent: the rejected second provider was never created.
    code_missing = _error_code(
        lambda: iot.describe_certificate_provider(certificateProviderName=second_name)
    )
    assert code_missing == ("ResourceNotFoundException", f"Certificate provider with name [{second_name}] not found"), (
        f"expected the rejected create to leave no provider behind, describe returned {code_missing}"
    )

    # Delete the first provider -- this must succeed and free the account slot.
    iot.delete_certificate_provider(certificateProviderName=name)
    code_gone = _error_code(
        lambda: iot.describe_certificate_provider(certificateProviderName=name)
    )
    assert code_gone == ("ResourceNotFoundException", f"Certificate provider with name [{name}] not found"), (
        f"expected the deleted provider to be gone, describe returned {code_gone}"
    )

    # Positive control: with the slot free, a fresh certificate provider succeeds.
    created2 = iot.create_certificate_provider(
        certificateProviderName=second_name,
        lambdaFunctionArn=fn_arn,
        accountDefaultForOperations=["CreateCertificateFromCsr"],
    )
    ctx.on_cleanup(lambda: _safe_delete(iot, second_name))
    assert created2["certificateProviderName"] == second_name, (
        f"expected create to echo {second_name!r}, got {created2.get('certificateProviderName')!r}"
    )

    # An independent describe proves the freed default was reclaimed.
    described2 = iot.describe_certificate_provider(certificateProviderName=second_name)
    assert described2["certificateProviderName"] == second_name, (
        f"expected describe to report {second_name!r}, got {described2.get('certificateProviderName')!r}"
    )
    assert described2["accountDefaultForOperations"] == ["CreateCertificateFromCsr"], (
        "expected the reclaimed slot's describe to report "
        f"accountDefaultForOperations=['CreateCertificateFromCsr'], got {described2.get('accountDefaultForOperations')!r}"
    )


def _try(fn):
    try:
        return fn()
    except ClientError:
        return None


def _safe_delete_fn(lam, fn_name: str) -> None:
    try:
        lam.delete_function(FunctionName=fn_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete(iot, name: str) -> None:
    try:
        iot.delete_certificate_provider(certificateProviderName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
