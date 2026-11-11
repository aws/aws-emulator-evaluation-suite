"""certificate-provider-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-provider-lifecycle"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control",
      "resource:account-singleton:iot-certificate-provider")
def run(ctx) -> None:
    """A created certificate provider describes back as created; after delete, both describe and
    UpdateCertificateProvider on the name fail with ResourceNotFoundException."""
    iot = ctx.client("iot")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    # CreateCertificateProvider invokes the Lambda during validation, so it must be real.
    lambda_arn = _create_lambda_function(ctx, iam, lam)

    name = ctx.unique_name("sim2real-cert-provider-")
    created = _retry_while(
        lambda: iot.create_certificate_provider(
            certificateProviderName=name,
            lambdaFunctionArn=lambda_arn,
            accountDefaultForOperations=["CreateCertificateFromCsr"],
            tags=[{"Key": "sim2real", "Value": "behavioral"}],
        ),
        retry_codes={"InvalidRequestException"},
        timeout_s=30.0,
    )
    ctx.on_cleanup(lambda: _delete_provider_quiet(iot, name))
    assert created["certificateProviderName"] == name, (
        f"expected create response certificateProviderName {name!r}, got "
        f"{created['certificateProviderName']!r}"
    )

    described = iot.describe_certificate_provider(certificateProviderName=name)
    assert described["certificateProviderName"] == name, (
        f"expected described certificateProviderName {name!r}, got "
        f"{described['certificateProviderName']!r}"
    )
    assert described["lambdaFunctionArn"] == lambda_arn, (
        f"expected lambdaFunctionArn {lambda_arn!r}, got {described['lambdaFunctionArn']!r}"
    )
    assert described["accountDefaultForOperations"] == ["CreateCertificateFromCsr"], (
        "expected accountDefaultForOperations ['CreateCertificateFromCsr'], got "
        f"{described['accountDefaultForOperations']!r}"
    )

    iot.delete_certificate_provider(certificateProviderName=name)

    code = _error_code(lambda: iot.describe_certificate_provider(certificateProviderName=name))
    assert code == ("ResourceNotFoundException", f"Certificate provider with name [{name}] not found"), (
        f"expected ResourceNotFoundException on describe after delete, got {code!r}"
    )

    # a mutation on the deleted name must not silently re-create the provider
    update_code = _error_code(
        lambda: iot.update_certificate_provider(
            certificateProviderName=name, lambdaFunctionArn=lambda_arn
        )
    )
    assert update_code == ("ResourceNotFoundException", f"Certificate provider with name [{name}] not found"), (
        f"expected ResourceNotFoundException on update of deleted provider, got {update_code!r}"
    )


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_while(fn, retry_codes, timeout_s=20.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _lambda_zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "index.py",
            "def handler(event, context):\n"
            "    return {'certificateId': 'sim2real-fake-cert-id', 'certificatePem': 'sim2real-fake-pem'}\n",
        )
    return buf.getvalue()


def _create_lambda_function(ctx, iam, lam):
    role_name = ctx.unique_name("sim2real-cp-lambda-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Role"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    def _cleanup_role():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    function_name = ctx.unique_name("sim2real-cp-fn-")
    ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
    created_fn = _retry_while(
        lambda: lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role["Arn"],
            Handler="index.handler",
            Code={"ZipFile": _lambda_zip_bytes()},
            Timeout=10,
            Tags={"sim2real": "behavioral"},
        ),
        retry_codes={"InvalidParameterValueException"},
        timeout_s=30.0,
    )

    def _cleanup_fn():
        try:
            lam.delete_function(FunctionName=function_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_fn)

    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-iot-invoke",
        Action="lambda:InvokeFunction",
        Principal="iot.amazonaws.com",
    )

    # Newly created Lambda functions/roles can take a moment before IoT's validation
    # invoke against them succeeds; poll GetFunction until it reports Active.
    _poll_until(
        lambda: lam.get_function(FunctionName=function_name)["Configuration"],
        lambda cfg: cfg.get("State") in ("Active", None),
        timeout_s=30.0,
        interval_s=2.0,
    )

    return created_fn["FunctionArn"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_provider_quiet(iot, name):
    try:
        iot.delete_certificate_provider(certificateProviderName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
