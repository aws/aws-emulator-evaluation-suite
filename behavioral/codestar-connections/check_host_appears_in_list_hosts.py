"""host-appears-in-list-hosts."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "host-appears-in-list-hosts"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


def _list_all_hosts(csc) -> list[dict]:
    hosts: list[dict] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = csc.list_hosts(**kwargs)
        hosts.extend(resp.get("Hosts", []))
        token = resp.get("NextToken")
        if not token:
            break
    return hosts


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created host is discoverable via ListHosts with matching fields."""
    csc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-behav-host-")
    endpoint = "https://ghes.example.org"

    arn = csc.create_host(
        Name=name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint=endpoint,
        Tags=[{"Key": "sim2real-purpose", "Value": "behavioral-check"}],
    )["HostArn"]
    ctx.on_cleanup(lambda: csc.delete_host(HostArn=arn))

    matches = [h for h in _list_all_hosts(csc) if h["HostArn"] == arn]
    assert len(matches) == 1, f"expected exactly one host with arn {arn}, got {matches}"
    assert matches[0]["Name"] == name, f"expected Name {name!r}, got {matches[0]['Name']!r}"
    assert matches[0]["ProviderEndpoint"] == endpoint, (
        f"expected ProviderEndpoint {endpoint!r}, got {matches[0]['ProviderEndpoint']!r}"
    )
    assert matches[0]["Status"] == "PENDING", f"expected Status PENDING, got {matches[0]['Status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
