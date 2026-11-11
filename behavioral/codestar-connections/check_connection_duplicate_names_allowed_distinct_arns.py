"""connection-duplicate-names-allowed-distinct-arns."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-duplicate-names-allowed-distinct-arns"
GROUP = "lifecycle"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection succeeds twice with the same ConnectionName, returning two distinct ARNs that
    GetConnection each resolves to that name and its own ARN.
    """
    csc = ctx.client("codestar-connections")
    name = ctx.unique_name("sim2real-behav-dupe-")

    arn1 = csc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=arn1))
    arn2 = csc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=arn2))

    assert arn1 != arn2, f"expected two distinct ConnectionArns for duplicate name {name!r}, got {arn1!r} twice"

    c1 = csc.get_connection(ConnectionArn=arn1)["Connection"]
    c2 = csc.get_connection(ConnectionArn=arn2)["Connection"]
    assert c1["ConnectionName"] == name, f"expected GetConnection({arn1}) name {name!r}, got {c1['ConnectionName']!r}"
    assert c2["ConnectionName"] == name, f"expected GetConnection({arn2}) name {name!r}, got {c2['ConnectionName']!r}"
    assert c1["ConnectionArn"] == arn1, f"expected GetConnection({arn1}) to echo its own arn, got {c1['ConnectionArn']!r}"
    assert c2["ConnectionArn"] == arn2, f"expected GetConnection({arn2}) to echo its own arn, got {c2['ConnectionArn']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
