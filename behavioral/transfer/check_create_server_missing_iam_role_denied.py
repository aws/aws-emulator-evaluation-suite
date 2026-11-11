"""create-server-missing-iam-role-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-server-missing-iam-role-denied"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateServer with an API_GATEWAY identity provider whose role cannot invoke the given URL fails
    with InvalidRequestException "Unable to verify access to API <url>" and creates no server carrying its
    Name tag, while a SERVICE_MANAGED server is created and described."""
    transfer = ctx.client("transfer")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-badrole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # IAM role creation is eventually consistent -- wait until the role itself is visible
    # before handing its ARN to CreateServer, so a stray NoSuchEntity-shaped failure can never
    # be mistaken for the InvalidRequestException this check is actually asserting.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            iam.get_role(RoleName=role_name)
            break
        except iam.exceptions.NoSuchEntityException:
            if time.monotonic() >= deadline:
                raise AssertionError(f"role {role_name!r} did not become visible in time")
            time.sleep(2.0)

    before = {s["ServerId"] for s in _list_all_servers(transfer)}

    attempt_name = ctx.unique_name("sim2real-behav-rejected-server-")
    url = ctx.api_url("a1b2c3d4e5", "prod")  # an invoke URL on the target for an API that does not exist
    error = _client_error(
        lambda: transfer.create_server(
            IdentityProviderType="API_GATEWAY",
            IdentityProviderDetails={"Url": url, "InvocationRole": role_arn},
            Tags=[{"Key": "Name", "Value": attempt_name}],
        )
    )
    assert error == ("InvalidRequestException", f"Unable to verify access to API {url}"), error

    # Effect absent: no server carrying the rejected attempt's unique Name tag exists. Only
    # servers that appeared since the attempt are inspected, so other tenants' servers are
    # never asserted on.
    for new_id in {s["ServerId"] for s in _list_all_servers(transfer)} - before:
        tags = transfer.describe_server(ServerId=new_id)["Server"].get("Tags", [])
        assert {"Key": "Name", "Value": attempt_name} not in tags, (
            f"server {new_id} was created despite the unverifiable identity provider API"
        )

    # Positive control: CreateServer without a custom identity provider (default
    # SERVICE_MANAGED) succeeds normally.
    server_name = ctx.unique_name("sim2real-behav-ctlserver-")
    created = transfer.create_server(Tags=[{"Key": "Name", "Value": server_name}])
    server_id = created["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    described = transfer.describe_server(ServerId=server_id)["Server"]
    assert described["ServerId"] == server_id, (
        f"expected the positive-control server {server_id!r} to describe itself, got {described!r}"
    )


def _client_error(fn):
    """The (code, message) of the ClientError ``fn`` raises; raises AssertionError on success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _list_all_servers(transfer):
    servers = []
    kwargs: dict = {}
    while True:
        resp = transfer.list_servers(**kwargs)
        servers.extend(resp.get("Servers", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs = {"NextToken": token}
    return servers


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


