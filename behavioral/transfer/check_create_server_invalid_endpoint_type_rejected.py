"""create-server-invalid-endpoint-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-server-invalid-endpoint-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateServer(EndpointType=PUBLIC, Protocols=[FTP]) fails with InvalidRequestException "FTP and FTPS protocols
    unsupported for IdentityProviderType SERVICE_MANAGED" and creates no server, while a PUBLIC SFTP server is created
    and describes with EndpointType PUBLIC and Protocols [SFTP]."""
    transfer = ctx.client("transfer")

    before_ids = _server_ids(transfer)

    rejected_name = ctx.unique_name("sim2real-transfer-srv-")
    error = _client_error(
        ctx,
        transfer,
        lambda: transfer.create_server(
            EndpointType="PUBLIC",
            Protocols=["FTP"],
            Tags=[{"Key": "Name", "Value": rejected_name}],
        ),
    )
    assert error == ("InvalidRequestException", "FTP and FTPS protocols unsupported for IdentityProviderType SERVICE_MANAGED"), error

    # Effect absent: no new server was created as a side effect of the rejected call.
    created = _tagged_servers(transfer, _server_ids(transfer) - before_ids, "Name", rejected_name)
    assert created == [], f"a server was created despite the rejected request: {created}"

    # Positive control: PUBLIC + SFTP (the one protocol PUBLIC actually supports) works.
    server_id = transfer.create_server(
        EndpointType="PUBLIC",
        Protocols=["SFTP"],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    described = transfer.describe_server(ServerId=server_id)["Server"]
    assert described["EndpointType"] == "PUBLIC", (
        f"expected EndpointType PUBLIC, got {described['EndpointType']!r}"
    )
    assert described["Protocols"] == ["SFTP"], (
        f"expected Protocols ['SFTP'], got {described['Protocols']!r}"
    )


def _server_ids(transfer) -> set[str]:
    ids: set[str] = set()
    for page in transfer.get_paginator("list_servers").paginate():
        ids.update(server["ServerId"] for server in page.get("Servers", []))
    return ids


def _tagged_servers(transfer, ids, key, value) -> list[str]:
    """The servers among ids tagged key=value; one already deleted is not this check's, since
    this check deletes nothing before its teardown."""
    own = []
    for server_id in sorted(ids):
        try:
            server = transfer.describe_server(ServerId=server_id)["Server"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
            raise
        if {"Key": key, "Value": value} in server.get("Tags", []):
            own.append(server_id)
    return own


def _client_error(ctx, transfer, fn):
    """Return the ClientError (code, message), or raise on unexpected SUCCESS."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    server_id = result.get("ServerId")
    if server_id:
        ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    raise AssertionError(
        f"expected CreateServer(EndpointType=PUBLIC, Protocols=[FTP]) to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
