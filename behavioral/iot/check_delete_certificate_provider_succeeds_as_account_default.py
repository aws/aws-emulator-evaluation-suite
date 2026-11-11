"""delete-certificate-provider-succeeds-as-account-default."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "delete-certificate-provider-succeeds-as-account-default"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control",
      "resource:account-singleton:iot-certificate-provider")
def run(ctx) -> None:
    """DeleteCertificateProvider succeeds on the account-default provider and removes it, and a
    later CreateCertificateFromCsr falls back to issuing an AWS-signed certificate."""
    iot = ctx.client("iot")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    provider_a = ctx.unique_name("sim2real-certprov-a-")

    role_arn = _create_lambda_execution_role(ctx, iam, ctx.unique_name("sim2real-certprov-role-"))
    fn_a_arn = _create_minimal_lambda(ctx, lam, ctx.unique_name("sim2real-certprov-fn-a-"), role_arn)

    iot.create_certificate_provider(
        certificateProviderName=provider_a,
        lambdaFunctionArn=fn_a_arn,
        accountDefaultForOperations=["CreateCertificateFromCsr"],
    )
    ctx.on_cleanup(lambda: _best_effort_delete(iot, provider_a))

    # the provider is the live account default, but AWS IoT does not block
    # deletion on that basis alone
    iot.delete_certificate_provider(certificateProviderName=provider_a)

    # effect present: the provider is actually gone, not a silent no-op
    code_after, message_after = _error(
        lambda: iot.describe_certificate_provider(certificateProviderName=provider_a)
    )
    assert code_after == "ResourceNotFoundException", (
        f"expected the provider to be gone after delete, got {code_after}"
    )
    expected = f"Certificate provider with name [{provider_a}] not found"
    assert message_after == expected, f"expected message {expected!r}, got {message_after!r}"

    # The deleted provider's still-permissioned Lambda stub would return an empty
    # certificatePem, so a real PEM proves the account default was cleared.
    csr_pem = _self_signed_csr_pem()
    csr_resp = iot.create_certificate_from_csr(certificateSigningRequest=csr_pem)
    ctx.on_cleanup(lambda: _best_effort_delete_certificate(iot, csr_resp["certificateId"]))
    assert csr_resp["certificatePem"].startswith("-----BEGIN CERTIFICATE-----"), (
        f"expected a real AWS-signed certificate, not a provider-issued stub, "
        f"got certificatePem={csr_resp['certificatePem']!r}"
    )
    assert csr_resp["certificateId"], "expected a non-empty AWS-issued certificateId"


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _self_signed_csr_pem() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real.example.com")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _best_effort_delete(iot, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iot.delete_certificate_provider(certificateProviderName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete_certificate(iot, cert_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_lambda_execution_role(ctx, iam, role_name: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn))
    # IAM role propagation lag is waited out by _create_minimal_lambda's bounded retry.
    return role_arn


def _create_minimal_lambda(ctx, lam, fn_name: str, role_arn: str) -> str:
    from botocore.exceptions import ClientError

    code = (
        "def handler(event, context):\n"
        "    return {\"certificatePem\": \"\", \"certificateId\": \"\"}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    zip_bytes = buf.getvalue()

    deadline = time.monotonic() + 60
    while True:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    # CreateCertificateProvider validates that the Lambda function is invocable
    # right away, so wait for it to leave Pending state before referencing it.
    deadline = time.monotonic() + 60
    while True:
        state = lam.get_function(FunctionName=fn_name)["Configuration"]["State"]
        if state == "Active":
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"lambda function {fn_name} never became Active, stuck at {state}")
        time.sleep(2)

    # AWS IoT invokes the certificate provider's Lambda function directly, so it
    # needs an explicit resource-based permission -- IAM role permissions alone
    # (which only govern what the function itself can call) are not enough.
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-allow-iot-invoke",
        Action="lambda:InvokeFunction",
        Principal="iot.amazonaws.com",
    )
    return resp["FunctionArn"]


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
