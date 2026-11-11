"""create-connection-nonexistent-host-arn-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connection-nonexistent-host-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


def _error(fn):
    """Call fn(); return its error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection with a HostArn in another account fails with AccessDeniedException and its exact message,
    ListConnections filtered on that host fails the same way, and a plain CreateConnection succeeds PENDING.
    """
    csc = ctx.client("codestar-connections")
    # Deliberately a different account than the caller's own, so the rejection is a
    # cross-account authorization denial, not a resource-not-found lookup.
    fake_host_arn = f"arn:aws:codestar-connections:{ctx.region}:111122223333:host/{uuid.uuid4()}"

    expected_message = f"Account {ctx.account} does not have access to host {fake_host_arn}"
    err = _error(
        lambda: csc.create_connection(
            ConnectionName=ctx.unique_name("sim2real-behav-bad-"),
            HostArn=fake_host_arn,
        )
    )
    assert err["Code"] == "AccessDeniedException", err
    assert err["Message"] == expected_message, err["Message"]

    # Effect absent: nothing was created under this (foreign-account) host.
    list_err = _error(lambda: csc.list_connections(HostArnFilter=fake_host_arn))
    assert list_err["Code"] == "AccessDeniedException", list_err
    assert list_err["Message"] == expected_message, list_err["Message"]

    # Positive control: a direct connection (no HostArn) still succeeds.
    control_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-ctl-"), ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=control_arn))
    status = csc.get_connection(ConnectionArn=control_arn)["Connection"]["ConnectionStatus"]
    assert status == "PENDING", status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
