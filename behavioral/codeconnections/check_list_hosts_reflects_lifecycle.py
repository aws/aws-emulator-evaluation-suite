"""list-hosts-reflects-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-hosts-reflects-lifecycle"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHosts reflects the current set of hosts: both newly created ones appear, and
    a deleted one disappears while its sibling remains."""
    cc = ctx.client("codeconnections")
    name_a = ctx.unique_name("sim2real-host-a-")[:64]
    name_b = ctx.unique_name("sim2real-host-b-")[:64]
    arn_a = cc.create_host(
        Name=name_a,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe-a.example.com",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["HostArn"]
    arn_b = cc.create_host(
        Name=name_b,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe-b.example.com",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["HostArn"]
    ctx.on_cleanup(lambda: cc.delete_host(HostArn=arn_b))

    arns = {h["HostArn"] for h in _iter_hosts(cc)}
    assert arn_a in arns
    assert arn_b in arns

    cc.delete_host(HostArn=arn_a)

    arns_after = {h["HostArn"] for h in _iter_hosts(cc)}
    assert arn_a not in arns_after
    assert arn_b in arns_after


def _iter_hosts(cc):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_hosts(**kwargs)
        yield from resp.get("Hosts", [])
        token = resp.get("NextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
