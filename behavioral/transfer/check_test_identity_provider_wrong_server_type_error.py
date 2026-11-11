"""test-identity-provider-wrong-server-type-error."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "test-identity-provider-wrong-server-type-error"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestIdentityProvider on a default SERVICE_MANAGED server is InvalidRequestException, distinct
    from ResourceNotFoundException for a missing server; an AWS_LAMBDA server returns the
    function's own response."""
    transfer = ctx.client("transfer")
    server_id = transfer.create_server()["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    described = transfer.describe_server(ServerId=server_id)["Server"]
    assert described["IdentityProviderType"] == "SERVICE_MANAGED", (
        f"expected a freshly created server to default to SERVICE_MANAGED, "
        f"got {described.get('IdentityProviderType')!r}"
    )

    code, message = _error(
        lambda: transfer.test_identity_provider(ServerId=server_id, UserName="sim2real-probe-user")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = f"{server_id} not configured for external auth"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    bogus_server_id = "s-" + "0" * 17
    not_found_code, not_found_message = _error(
        lambda: transfer.test_identity_provider(ServerId=bogus_server_id, UserName="sim2real-probe-user")
    )
    assert not_found_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {not_found_code!r}"
    assert not_found_message == "Unknown server", (
        f"expected message 'Unknown server', got {not_found_message!r}"
    )
    assert code != not_found_code, "the two failure modes must not collapse into the same error code"

    # Positive control: the rejection above is specific to SERVICE_MANAGED.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    marker = f"sim2real-marker-{uuid.uuid4().hex}"
    fn_arn, fn_name = _create_mock_idp_lambda(ctx, marker, account_id)

    lambda_server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="AWS_LAMBDA",
        Domain="S3",
        EndpointType="PUBLIC",
        IdentityProviderDetails={"Function": fn_arn},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-lambda-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=lambda_server_id))

    server_arn = f"arn:aws:transfer:{ctx.region}:{account_id}:server/{lambda_server_id}"
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId="transfer-invoke",
            Action="lambda:InvokeFunction",
            Principal="transfer.amazonaws.com",
            SourceArn=server_arn,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e):
            raise

    response = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        response = transfer.test_identity_provider(
            ServerId=lambda_server_id,
            UserName="sim2real-probe-user",
            UserPassword="does-not-matter",
            ServerProtocol="SFTP",
        )
        if response["StatusCode"] == 200:
            break
        time.sleep(3)

    assert response is not None, "TestIdentityProvider never returned StatusCode 200 within 60s"
    assert response["StatusCode"] == 200, f"expected StatusCode 200 from a real Lambda-backed IdP, got {response}"
    resp_text = response.get("Response", "")
    assert marker in resp_text, (
        f"TestIdentityProvider did not surface the real Lambda response body: {resp_text!r} "
        f"msg={response.get('Message', '')!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_mock_idp_lambda(ctx, marker: str, account_id: str) -> tuple[str, str]:
    """A Lambda custom identity provider whose HomeDirectory carries a unique marker, so the
    check can tell the function's own output was returned."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-transfer-idp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )

    def _delete_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="logs")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)

    mock_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-idp-mock-role"
    home_directory = f"/sim2real-idp-test/{marker}"
    handler_code = (
        "def lambda_handler(event, context):\n"
        f"    return {{'Role': {mock_role_arn!r}, 'HomeDirectory': {home_directory!r}}}\n"
    )

    fn_name = ctx.unique_name("sim2real-transfer-idp-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)

    deadline = time.monotonic() + 40
    last_err = None
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            fn_arn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_buf.getvalue()},
                Timeout=10,
                MemorySize=128,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-transfer-idp"},
            )["FunctionArn"]
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

    return fn_arn, fn_name


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
