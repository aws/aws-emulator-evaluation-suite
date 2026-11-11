"""create-connection-on-deleted-host-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connection-on-deleted-host-rejected"
GROUP = "overly-permissive"
SERVICES = ["codestar-connections"]


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnection on a deleted host's ARN fails with ResourceNotFoundException and its exact message,
    ListConnections filtered on that host fails the same way, and a plain CreateConnection succeeds PENDING.
    """
    csc = ctx.client("codestar-connections")

    host_arn = csc.create_host(
        Name=ctx.unique_name("sim2real-behav-host-"),
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghes.example.com",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["HostArn"]
    status = csc.get_host(HostArn=host_arn)["Status"]
    assert status == "PENDING", status
    csc.delete_host(HostArn=host_arn)

    expected_message = f"No host exists with the ARN: {host_arn}"
    err = _error(
        lambda: csc.create_connection(
            ConnectionName=ctx.unique_name("sim2real-behav-conn-"),
            HostArn=host_arn,
        )
    )
    assert err["Code"] == "ResourceNotFoundException", err
    assert err["Message"] == expected_message, err["Message"]

    # Effect absent: no connection got created under this deleted host.
    list_err = _error(lambda: csc.list_connections(HostArnFilter=host_arn))
    assert list_err["Code"] == "ResourceNotFoundException", list_err
    assert list_err["Message"] == expected_message, list_err["Message"]

    # Positive control: a direct (hostless) connection still succeeds.
    control_arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-ctl-"),
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=control_arn))
    control_status = csc.get_connection(ConnectionArn=control_arn)["Connection"]["ConnectionStatus"]
    assert control_status == "PENDING", control_status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

