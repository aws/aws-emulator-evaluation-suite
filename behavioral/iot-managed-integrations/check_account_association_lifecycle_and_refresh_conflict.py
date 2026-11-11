"""account-association-lifecycle-and-refresh-conflict."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-association-lifecycle-and-refresh-conflict"
GROUP = "state-machine"
SERVICES = ["iot-managed-integrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAccountAssociation on a deleted destination fails with ValidationException;
    a real one starts ASSOCIATION_IN_PROGRESS, a second create fails with
    ConflictException, and after delete it succeeds."""
    iot = _iot_client(ctx)
    lam = _lambda_client(ctx)
    sm = _secrets_client(ctx)

    connector_id = _create_cloud_connector(ctx, iot, lam)

    # A well-formed but never-created id is rejected as missing; a made-up slug that
    # does not match the service's own id shape is rejected as malformed input before
    # the not-found check ever runs, so the "missing" case has to be a real id that
    # existed and no longer does.
    stale_destination_id = _create_connector_destination(ctx, iot, sm, connector_id)
    iot.delete_connector_destination(Identifier=stale_destination_id)
    gone_error = _error(
        lambda: iot.get_connector_destination(Identifier=stale_destination_id),
        "get-connector-destination-after-delete",
    )
    assert gone_error["Code"] == "ResourceNotFoundException", gone_error
    assert gone_error.get("Message") == 'Connector Destination not found', gone_error

    missing_error = _error(
        lambda: iot.create_account_association(ConnectorDestinationId=stale_destination_id),
        "create-account-association-on-deleted-destination",
    )
    # AWS answers a deleted destination id here with ValidationException, not the
    # ResourceNotFoundException the other not-found paths in this file return.
    assert missing_error["Code"] == "ValidationException", missing_error
    assert missing_error.get("Message") == 'Connector Destination in the request does not exist.', missing_error

    destination_id = _create_connector_destination(ctx, iot, sm, connector_id)

    created = iot.create_account_association(
        ConnectorDestinationId=destination_id, Tags={"sim2real": "true"}
    )
    association_id = created["AccountAssociationId"]
    assert created["AssociationState"] == "ASSOCIATION_IN_PROGRESS", created["AssociationState"]
    ctx.on_cleanup(lambda: _delete_association_ignore_missing(iot, association_id))

    got = iot.get_account_association(AccountAssociationId=association_id)
    assert got["AssociationState"] == "ASSOCIATION_IN_PROGRESS", got

    # A refresh of the still-outstanding association is NOT a conflict: it succeeds
    # and reissues the OAuth authorization URL for the same association. The response
    # carries only the URL, so the independent read below proves the association is unaffected.
    refreshed = iot.start_account_association_refresh(AccountAssociationId=association_id)
    assert refreshed["OAuthAuthorizationUrl"].startswith("https://example.com/oauth2/authorize"), (
        refreshed
    )
    unaffected = iot.get_account_association(AccountAssociationId=association_id)
    assert unaffected["AssociationState"] == "ASSOCIATION_IN_PROGRESS", unaffected
    assert unaffected["AccountAssociationId"] == association_id, unaffected

    # Break exactly one thing: a SECOND CreateAccountAssociation on the same
    # destination while the first is still outstanding.
    dup_error = _error(
        lambda: iot.create_account_association(ConnectorDestinationId=destination_id),
        "duplicate-create-while-outstanding",
    )
    assert dup_error["Code"] == "ConflictException", dup_error
    assert dup_error.get("Message") == 'Account Association conflicts with existing record.', dup_error

    # Effect absent: the original association is untouched by the rejected duplicate.
    still_in_progress = iot.get_account_association(AccountAssociationId=association_id)
    assert still_in_progress["AssociationState"] == "ASSOCIATION_IN_PROGRESS", still_in_progress
    assert still_in_progress["AccountAssociationId"] == association_id, still_in_progress

    iot.delete_account_association(AccountAssociationId=association_id)
    not_found_error = _error(
        lambda: iot.get_account_association(AccountAssociationId=association_id),
        "get-account-association-after-delete",
    )
    assert not_found_error["Code"] == "ResourceNotFoundException", not_found_error
    assert not_found_error.get("Message") == 'Account association not found.', not_found_error

    # Restore: with the outstanding association gone, the identical create now succeeds.
    restored = iot.create_account_association(
        ConnectorDestinationId=destination_id, Tags={"sim2real": "true"}
    )
    restored_id = restored["AccountAssociationId"]
    assert restored["AssociationState"] == "ASSOCIATION_IN_PROGRESS", restored
    assert restored_id != association_id, restored
    ctx.on_cleanup(lambda: _delete_association_ignore_missing(iot, restored_id))


def _iot_client(ctx):
    # iot-managed-integrations is offered in ca-central-1 and eu-west-1 only, so this client
    # pins the region; ctx.client keeps the run's credentials and endpoint routing.
    from botocore.config import Config

    return ctx.client(
        "iot-managed-integrations",
        region="eu-west-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )
def _lambda_client(ctx):
    # The cloud connector's endpoint Lambda must live where the connector does
    # (see _iot_client) so the referenced ARN's region matches the caller's.
    return ctx.client("lambda", region="eu-west-1")
def _secrets_client(ctx):
    # The connector destination's SecretsManagerArn must resolve in the same region
    # as the destination itself (see _iot_client).
    return ctx.client("secretsmanager", region="eu-west-1")
def _error(fn, what: str) -> dict:
    # An unexpected SUCCESS raises rather than returning a falsy sentinel.
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"{what}: expected a ClientError, call succeeded with {result!r}")


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
    name = ctx.unique_name("sim2real-c2c-fn-role-")
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


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _wait_active(lam, name: str, timeout_s: float = 60) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Failed":
            raise AssertionError(f"{name} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{name} did not reach Active within {timeout_s}s: {last!r}")


def _deploy_endpoint_lambda(ctx, lam) -> str:
    # CreateCloudConnector's EndpointConfig requires a Lambda ARN that actually
    # resolves to a real function -- a made-up ARN is rejected with ValidationException
    # ("Connector endpoint Lambda ARN does not exist") before the connector is ever
    # created, so the endpoint function has to be real, not a placeholder string.
    role_arn = _create_lambda_role(ctx)
    name = ctx.unique_name("sim2real-c2c-fn-")
    created = _create_function_when_role_assumable(
        lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _make_zip("def handler(event, context): return event")},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _delete_function_ignore_missing(lam, name))
    _wait_active(lam, name)
    return created["FunctionArn"]


def _delete_function_ignore_missing(lam, name: str) -> None:
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_cloud_connector(ctx, iot, lam) -> str:
    lambda_arn = _deploy_endpoint_lambda(ctx, lam)
    created = iot.create_cloud_connector(
        Name=ctx.unique_name("sim2real-connector-"),
        EndpointType="LAMBDA",
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


def _create_connector_destination(ctx, iot, sm, connector_id: str) -> str:
    # OAUTH requires the client id/secret to live in Secrets Manager and be named by
    # ARN + version -- CreateConnectorDestination rejects a request with no
    # SecretsManagerArn ("cannot be null or empty") before it ever looks at AuthConfig.
    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-c2c-oauth-"),
        SecretString=json.dumps({"clientId": "sim2real-client", "clientSecret": "sim2real-secret"}),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True)
    )

    created = iot.create_connector_destination(
        CloudConnectorId=connector_id,
        AuthType="OAUTH",
        AuthConfig={
            "oAuth": {
                "authUrl": "https://example.com/oauth2/authorize",
                "tokenUrl": "https://example.com/oauth2/token",
                "tokenEndpointAuthenticationScheme": "HTTP_BASIC",
            }
        },
        SecretsManager={"arn": secret["ARN"], "versionId": secret["VersionId"]},
        Name=ctx.unique_name("sim2real-condest-"),
    )
    destination_id = created["Id"]

    def _cleanup():
        try:
            iot.delete_connector_destination(Identifier=destination_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return destination_id


def _delete_association_ignore_missing(iot, association_id: str) -> None:
    try:
        iot.delete_account_association(AccountAssociationId=association_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
