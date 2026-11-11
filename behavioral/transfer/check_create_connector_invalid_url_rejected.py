"""create-connector-invalid-url-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-connector-invalid-url-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnector requires exactly one of As2Config/SftpConfig; supplying only a raw Url
    with neither is rejected with InvalidRequestException rather than accepted as a connector
    that could never actually route a transfer."""
    transfer = ctx.client("transfer")
    iam = ctx.client("iam")

    role_arn = _create_transfer_role(ctx, iam, "sim2real-behav-connrole-")

    before = _list_all_connectors(transfer)

    error = _client_error(
        lambda: transfer.create_connector(
            AccessRole=role_arn, Url="https://partner.example.com/as2"
        )
    )
    assert error == ("InvalidRequestException", "One of As2Config or SftpConfig must be specified"), error

    after_reject = _list_all_connectors(transfer)
    created = _own_connectors(transfer, set(after_reject) - set(before), role_arn)
    assert created == [], f"a connector was created despite missing As2Config/SftpConfig: {created}"

    # Positive control: the same AccessRole, with a valid As2Config, succeeds.
    profiles = ctx.client("transfer")
    local_profile_name = ctx.unique_name("local-")[:60]
    local_profile_id = profiles.create_profile(
        As2Id=local_profile_name,
        ProfileType="LOCAL",
        Tags=[{"Key": "Name", "Value": local_profile_name}],
    )["ProfileId"]
    ctx.on_cleanup(lambda: profiles.delete_profile(ProfileId=local_profile_id))
    partner_profile_name = ctx.unique_name("partner-")[:60]
    partner_profile_id = profiles.create_profile(
        As2Id=partner_profile_name,
        ProfileType="PARTNER",
        Tags=[{"Key": "Name", "Value": partner_profile_name}],
    )["ProfileId"]
    ctx.on_cleanup(lambda: profiles.delete_profile(ProfileId=partner_profile_id))

    connector_id = _retry_role_propagation(
        lambda: transfer.create_connector(
            AccessRole=role_arn,
            Url="https://partner.example.com/as2",
            As2Config={
                "LocalProfileId": local_profile_id,
                "PartnerProfileId": partner_profile_id,
                "Compression": "DISABLED",
                "EncryptionAlgorithm": "AES256_CBC",
                "SigningAlgorithm": "NONE",
                "MdnSigningAlgorithm": "NONE",
                "MdnResponse": "NONE",
            },
            Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-connector-")}],
        )
    )["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    after_control = _list_all_connectors(transfer)
    created = _own_connectors(transfer, set(after_control) - set(before), role_arn)
    assert created == [connector_id], (
        f"expected exactly the one new connector {connector_id} on this AccessRole after the valid "
        f"As2Config call, got {created}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected CreateConnector to be rejected, but it succeeded and returned {result!r}"
    )


def _list_all_connectors(transfer):
    connectors = []
    kwargs: dict = {}
    while True:
        resp = transfer.list_connectors(**kwargs)
        connectors.extend(c["ConnectorId"] for c in resp.get("Connectors", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs = {"NextToken": token}
    return sorted(connectors)


def _own_connectors(transfer, ids, role_arn) -> list[str]:
    """The connectors among ids whose AccessRole is role_arn; one already deleted is not this
    check's, since this check deletes nothing before its teardown."""
    from botocore.exceptions import ClientError

    own = []
    for connector_id in sorted(ids):
        try:
            connector = transfer.describe_connector(ConnectorId=connector_id)["Connector"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
            raise
        if connector.get("AccessRole") == role_arn:
            own.append(connector_id)
    return own


def _create_transfer_role(ctx, iam, name_prefix: str) -> str:
    role_name = ctx.unique_name(name_prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _retry_role_propagation(fn, attempts: int = 6, delay_s: float = 3.0):
    """Retry a call that depends on a just-created IAM role, tolerating IAM's eventual consistency."""
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
