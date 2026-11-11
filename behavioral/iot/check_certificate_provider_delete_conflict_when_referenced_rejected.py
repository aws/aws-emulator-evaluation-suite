"""certificate-provider-delete-conflict-when-referenced-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-provider-delete-conflict-when-referenced-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control",
      "resource:account-singleton:iot-certificate-provider")
def run(ctx) -> None:
    """A duplicate-name CreateCertificateProvider is rejected and leaves the original untouched;
    delete removes the provider (Describe and Update 404, absent from List)."""
    fn_arn = _create_stub_lambda(ctx)
    iot = ctx.client("iot")

    provider_name = ctx.unique_name("sim2real-iot-certprovider-")
    create_resp = _retry_on_invoke_denied(
        lambda: iot.create_certificate_provider(
            certificateProviderName=provider_name,
            lambdaFunctionArn=fn_arn,
            accountDefaultForOperations=["CreateCertificateFromCsr"],
            tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        timeout_s=60,
    )
    provider_deleted = {"done": False}

    def _cleanup_provider():
        if not provider_deleted["done"]:
            try:
                iot.delete_certificate_provider(certificateProviderName=provider_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_provider)
    assert create_resp["certificateProviderName"] == provider_name, (
        f"expected CreateCertificateProvider to echo {provider_name!r}, "
        f"got {create_resp['certificateProviderName']!r}"
    )

    described = iot.describe_certificate_provider(certificateProviderName=provider_name)
    assert described["lambdaFunctionArn"] == fn_arn, (
        f"expected lambdaFunctionArn {fn_arn!r}, got {described['lambdaFunctionArn']!r}"
    )
    assert described["accountDefaultForOperations"] == ["CreateCertificateFromCsr"], (
        "expected accountDefaultForOperations ['CreateCertificateFromCsr'], "
        f"got {described['accountDefaultForOperations']!r}"
    )

    # negative: re-using the same name is rejected, and the original
    # provider's state is untouched by the rejected attempt
    code = _error_code(
        lambda: iot.create_certificate_provider(
            certificateProviderName=provider_name,
            lambdaFunctionArn=fn_arn,
            accountDefaultForOperations=["CreateCertificateFromCsr"],
        )
    )
    assert code == ("ResourceAlreadyExistsException", f"Certificate provider [{provider_name}] already exists for this account"), (
        f"expected ResourceAlreadyExistsException for a duplicate name, got {code!r}"
    )

    unaffected = iot.describe_certificate_provider(certificateProviderName=provider_name)
    assert unaffected["lambdaFunctionArn"] == fn_arn, (
        f"rejected duplicate-name create must not touch the original: expected "
        f"lambdaFunctionArn {fn_arn!r}, got {unaffected['lambdaFunctionArn']!r}"
    )
    assert unaffected["accountDefaultForOperations"] == ["CreateCertificateFromCsr"], (
        "rejected duplicate-name create must not touch the original: expected "
        f"accountDefaultForOperations ['CreateCertificateFromCsr'], got "
        f"{unaffected['accountDefaultForOperations']!r}"
    )

    # DeleteConflictException has no reproducible trigger: no IoT resource stores a
    # certificateProviderName back-reference, so only the plain delete is asserted.
    iot.delete_certificate_provider(certificateProviderName=provider_name)
    provider_deleted["done"] = True

    not_found_code = _error_code(
        lambda: iot.describe_certificate_provider(certificateProviderName=provider_name)
    )
    assert not_found_code == ("ResourceNotFoundException", f"Certificate provider with name [{provider_name}] not found"), (
        f"expected ResourceNotFoundException on Describe after delete, got {not_found_code!r}"
    )

    # a mutation against the now-dead id must also fail, not silently resurrect it; the
    # update carries a real field so the refusal is the missing provider, not an empty update.
    update_after_delete_code = _error_code(
        lambda: iot.update_certificate_provider(
            certificateProviderName=provider_name, lambdaFunctionArn=fn_arn
        )
    )
    assert update_after_delete_code == ("ResourceNotFoundException", f"Certificate provider with name [{provider_name}] not found"), (
        f"expected ResourceNotFoundException on Update after delete, got {update_after_delete_code!r}"
    )

    listed = iot.list_certificate_providers().get("certificateProviders", [])
    assert all(p["certificateProviderName"] != provider_name for p in listed), (
        f"deleted provider {provider_name!r} still present in ListCertificateProviders"
    )


_LAMBDA_SRC = """
def handler(event, context):
    return {"certificatePem": "", "certificateOwnershipToken": ""}
"""


def _lambda_zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_stub_lambda(ctx) -> str:
    lambda_client = ctx.client("lambda")
    iam = ctx.client("iam")
    fn_name = ctx.unique_name("sim2real-iot-certprovider-fn-")
    role_name = ctx.unique_name("sim2real-iot-certprovider-role-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    zip_bytes = _lambda_zip(_LAMBDA_SRC)

    def _create():
        ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
        return lambda_client.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=10,
            Publish=True,
            Tags={"sim2real": CHECK},
        )

    resp = _retry_on_codes(_create, codes=("InvalidParameterValueException",), timeout_s=60)
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=fn_name))
    lambda_client.get_waiter("function_active").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    fn_arn = resp["FunctionArn"]

    # CreateCertificateProvider synchronously invokes the Lambda to validate it,
    # so IoT's service principal needs explicit resource-policy permission.
    lambda_client.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-iot-invoke",
        Action="lambda:InvokeFunction",
        Principal="iot.amazonaws.com",
    )
    return fn_arn



def _retry_on_codes(fn, codes, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _retry_on_invoke_denied(fn, timeout_s=60.0, interval_s=3.0):
    """IAM/Lambda resource-policy permissions can take a few seconds to
    propagate; retry while CreateCertificateProvider reports it can't invoke
    the function yet."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "InvalidRequestException" and "access denied" in msg.lower():
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc



def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
