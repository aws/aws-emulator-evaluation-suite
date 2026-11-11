"""host-status-message-present-when-pending."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "host-status-message-present-when-pending"
GROUP = "state"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PENDING host created without a VPC configuration is listed exactly once by ListHosts and carries no
    StatusMessage, which only describes VPC-configuration states.
    """
    cc = ctx.client("codestar-connections")
    arn = cc.create_host(
        Name=ctx.unique_name("sim2real-host-"),
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
    )["HostArn"]
    ctx.on_cleanup(lambda: _safe_delete_host(cc, arn))

    matches = [h for h in _list_all_hosts(cc) if h["HostArn"] == arn]
    assert len(matches) == 1, f"expected exactly one host for {arn}, got {matches}"
    host = matches[0]
    assert host["Status"] == "PENDING", f"expected PENDING, got {host['Status']!r}"
    status_message = host.get("StatusMessage")
    assert status_message is None, (
        f"expected no StatusMessage for a host with no VPC configuration, "
        f"got {status_message!r}"
    )


def _list_all_hosts(cc) -> list[dict]:
    hosts: list[dict] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_hosts(**kwargs)
        hosts.extend(resp.get("Hosts", []))
        token = resp.get("NextToken")
        if not token:
            break
    return hosts


def _safe_delete_host(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_host(HostArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
