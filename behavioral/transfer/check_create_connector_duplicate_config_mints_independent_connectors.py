"""create-connector-duplicate-config-mints-independent-connectors."""
from __future__ import annotations

import json
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connector-duplicate-config-mints-independent-connectors"
GROUP = "negative-classes"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnector does not dedupe: two identical AS2 configurations mint distinct connectors,
    each listed and describable; deleting one leaves the other (ResourceNotFoundException after)."""
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    local_profile_id = _create_profile(ctx, "LOCAL")
    partner_profile_id = _create_profile(ctx, "PARTNER")

    url = "http://partner-as2.example.com"
    as2_config = {
        "LocalProfileId": local_profile_id,
        "PartnerProfileId": partner_profile_id,
        "MdnResponse": "NONE",
        "MdnSigningAlgorithm": "NONE",
        "Compression": "DISABLED",
        "EncryptionAlgorithm": "AES128_CBC",
        "SigningAlgorithm": "NONE",
    }

    resource_tags = [{"Key": "sim2real", "Value": "true"}]

    first = transfer.create_connector(
        Url=url, AccessRole=role_arn, As2Config=as2_config, Tags=resource_tags
    )
    first_id = first["ConnectorId"]
    ctx.on_cleanup(lambda: _delete_connector_if_present(transfer, first_id))

    second = transfer.create_connector(
        Url=url, AccessRole=role_arn, As2Config=as2_config, Tags=resource_tags
    )
    second_id = second["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=second_id))

    assert first_id != second_id, "identical CreateConnector calls collapsed onto one ConnectorId"

    # effect: both connectors independently exist with the identical Url
    matches = [
        c for c in _list_connectors(transfer) if c["ConnectorId"] in (first_id, second_id)
    ]
    assert len(matches) == 2, f"expected both connectors to be independently listed, found {matches}"

    described_first = transfer.describe_connector(ConnectorId=first_id)
    described_second = transfer.describe_connector(ConnectorId=second_id)
    assert described_first["Connector"]["Url"] == url, (
        f"expected {first_id} Url == {url!r}, got {described_first['Connector'].get('Url')!r}"
    )
    assert described_second["Connector"]["Url"] == url, (
        f"expected {second_id} Url == {url!r}, got {described_second['Connector'].get('Url')!r}"
    )

    # deleting one leaves the other untouched
    transfer.delete_connector(ConnectorId=first_id)
    not_found = _client_error(lambda: transfer.describe_connector(ConnectorId=first_id))
    assert not_found == ("ResourceNotFoundException", "Unknown connector"), not_found
    delete_again = _client_error(lambda: transfer.delete_connector(ConnectorId=first_id))
    assert delete_again == ("ResourceNotFoundException", "Unknown connector"), delete_again
    still_there = transfer.describe_connector(ConnectorId=second_id)
    assert still_there["Connector"]["ConnectorId"] == second_id, (
        f"expected {second_id} to remain describable after deleting {first_id}, "
        f"got {still_there['Connector'].get('ConnectorId')!r}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """The (code, message) of a refused call; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_connector_if_present(transfer, connector_id: str) -> None:
    try:
        transfer.delete_connector(ConnectorId=connector_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_connectors(transfer) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    paginator = transfer.get_paginator("list_connectors")
    for page in paginator.paginate():
        out.extend(page.get("Connectors", []))
    return out


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-connrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_profile(ctx, profile_type: str) -> str:
    transfer = ctx.client("transfer")
    as2_id = ctx.unique_name("sim2real-as2-").upper().replace("-", "")[:32]
    resp = transfer.create_profile(
        As2Id=as2_id,
        ProfileType=profile_type,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    profile_id = resp["ProfileId"]
    ctx.on_cleanup(lambda: transfer.delete_profile(ProfileId=profile_id))
    return profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
