"""connector-destination-referential-integrity."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connector-destination-referential-integrity"
GROUP = "crud-depth"
SERVICES = ["iot-managed-integrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnectorDestination with a nonexistent CloudConnectorId fails with
    ValidationException and its exact message; with a real one it reflects that id, and after
    delete Get and Update fail with ResourceNotFoundException."""
    iot = _iot_client(ctx)
    lam = _lambda_client(ctx)
    account_id = ctx.account
    auth_config = {
        "oAuth": {
            "authUrl": "https://example.com/oauth2/authorize",
            "tokenUrl": "https://example.com/oauth2/token",
            "tokenEndpointAuthenticationScheme": "HTTP_BASIC",
        }
    }
    secrets_manager = _create_oauth_secret(ctx)

    missing_code, missing_msg = _error(
        lambda: iot.create_connector_destination(
            CloudConnectorId="sim2real-bogus-cloud-connector-id",
            AuthConfig=auth_config,
            SecretsManager=secrets_manager,
        )
    )
    # A non-existent CloudConnectorId is rejected as ValidationException
    # ("The provided CloudConnectorId does not exist."), not ResourceNotFoundException -- the
    # referential check runs as request validation, ahead of any resource lookup.
    assert missing_code == "ValidationException", (
        f"expected ValidationException for a bogus CloudConnectorId, got {missing_code}: {missing_msg}"
    )
    assert missing_msg == 'The provided CloudConnectorId does not exist.', (
        f"expected the CloudConnectorId-does-not-exist message, got {missing_msg!r}"
    )

    connector_id = _create_cloud_connector(ctx, iot, lam, account_id)
    created = iot.create_connector_destination(
        CloudConnectorId=connector_id,
        AuthType="OAUTH",
        AuthConfig=auth_config,
        SecretsManager=secrets_manager,
        Name=ctx.unique_name("sim2real-condest-"),
    )
    destination_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_connector_destination_ignore_missing(iot, destination_id))

    got = iot.get_connector_destination(Identifier=destination_id)
    assert got["CloudConnectorId"] == connector_id, (
        f"expected CloudConnectorId {connector_id!r}, got {got['CloudConnectorId']!r}"
    )
    assert got["AuthType"] == "OAUTH", f"expected AuthType OAUTH, got {got['AuthType']!r}"

    iot.delete_connector_destination(Identifier=destination_id)
    not_found_code, not_found_msg = _error(
        lambda: iot.get_connector_destination(Identifier=destination_id)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"get after delete: expected ResourceNotFoundException, got {not_found_code}"
    )
    assert not_found_msg == 'Connector Destination not found', f"get after delete: got message {not_found_msg!r}"

    mutate_code, mutate_msg = _error(
        lambda: iot.update_connector_destination(Identifier=destination_id, Description="post-delete")
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"update on deleted destination: expected ResourceNotFoundException, got {mutate_code}"
    )
    assert mutate_msg == 'Connector destination cannot be found.', f"update on deleted destination: got message {mutate_msg!r}"


def _iot_client(ctx):
    # iot-managed-integrations is offered in ca-central-1 and eu-west-1 only, so this client
    # pins the region; ctx.client keeps the run's credentials and endpoint routing.
    return ctx.client("iot-managed-integrations", region="eu-west-1")


def _lambda_client(ctx):
    # The connector's Lambda endpoint is validated by a live lookup at CreateCloudConnector
    # time, so the function must exist where the connector call lands: eu-west-1 on real
    # AWS, same as _iot_client.
    return ctx.client("lambda", region="eu-west-1")


def _secrets_client(ctx):
    # CreateConnectorDestination's own OAuth existence check runs in the same region as
    # the connector call (eu-west-1 on real AWS, see _iot_client), and Secrets Manager
    # is regional, so the secret has to live there too.
    return ctx.client("secretsmanager", region="eu-west-1")


def _create_oauth_secret(ctx) -> dict:
    sm = _secrets_client(ctx)
    name = ctx.unique_name("sim2real-condest-secret-")
    created = sm.create_secret(Name=name, SecretString='{"clientId":"sim2real","clientSecret":"sim2real"}')
    secret_arn = created["ARN"]
    version_id = created["VersionId"]

    def _cleanup():
        try:
            sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": secret_arn, "versionId": version_id}


_LAMBDA_TRUST = json.dumps(
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
)


def _create_lambda_role(ctx) -> str:
    # The endpoint function only has to exist; it is never invoked, so its execution role
    # carries a trust policy and nothing else.
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cd-fn-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


def _create_function_when_role_assumable(lam, timeout_s: float = 60.0, **kwargs) -> dict:
    # IAM is eventually consistent: Lambda rejects a role created moments ago until it can
    # be assumed. Retry only that rejection, bounded by a deadline.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            err = e.response["Error"]
            propagating = err["Code"] == "InvalidParameterValueException" and "cannot be assumed" in (
                err.get("Message") or ""
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _wait_active(lam, fn_name: str, timeout_s: float = 60) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn_name)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn_name} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn_name} did not reach Active within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, account_id: str) -> str:
    role_arn = _create_lambda_role(ctx)
    fn_name = ctx.unique_name("sim2real-cd-fn-")
    _create_function_when_role_assumable(
        lam,
        FunctionName=fn_name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _make_zip("def handler(e, c): return e")},
        MemorySize=128,
        Timeout=10,
    )
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, fn_name))
    _wait_active(lam, fn_name)
    # The cloud connector's live existence check is made by the iotmanagedintegrations
    # service, not by this caller, so the function needs a resource policy granting that
    # service principal permission to look it up.
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-allow-iotmanagedintegrations",
        Action="lambda:InvokeFunction",
        Principal="iotmanagedintegrations.amazonaws.com",
        SourceAccount=account_id,
    )
    return fn_name


def _cleanup_function(ctx, lam, fn_name: str) -> None:
    try:
        lam.delete_function(FunctionName=fn_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs = ctx.client("logs", region="eu-west-1")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_cloud_connector(ctx, iot, lam, account_id: str) -> str:
    fn_name = _deploy_function(ctx, lam, account_id)
    lambda_arn = lam.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]
    created = iot.create_cloud_connector(
        Name=ctx.unique_name("sim2real-connector-"),
        EndpointConfig={"lambda": {"arn": lambda_arn}},
    )
    connector_id = created["Id"]

    def _cleanup():
        try:
            iot.delete_cloud_connector(Identifier=connector_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return connector_id


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_connector_destination_ignore_missing(iot, destination_id: str) -> None:
    try:
        iot.delete_connector_destination(Identifier=destination_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
