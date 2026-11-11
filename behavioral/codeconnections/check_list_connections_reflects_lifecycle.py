"""list-connections-reflects-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-connections-reflects-lifecycle"
GROUP = "state"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnections reflects the current set of connections: both newly created ones
    appear, and a deleted one disappears while its sibling remains."""
    cc = ctx.client("codeconnections")
    name_a = ctx.unique_name("sim2real-conn-a-")[:32]
    name_b = ctx.unique_name("sim2real-conn-b-")[:32]
    arn_a = cc.create_connection(ConnectionName=name_a, ProviderType="GitHub")["ConnectionArn"]
    arn_b = cc.create_connection(ConnectionName=name_b, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn_b))

    arns = {c["ConnectionArn"] for c in _iter_connections(cc)}
    assert arn_a in arns, f"expected {arn_a} in ListConnections after create, got {arns!r}"
    assert arn_b in arns, f"expected {arn_b} in ListConnections after create, got {arns!r}"

    cc.delete_connection(ConnectionArn=arn_a)

    arns_after = {c["ConnectionArn"] for c in _iter_connections(cc)}
    assert arn_a not in arns_after, (
        f"expected {arn_a} absent from ListConnections after delete, got {arns_after!r}"
    )
    assert arn_b in arns_after, (
        f"expected sibling {arn_b} to remain in ListConnections after deleting {arn_a}, "
        f"got {arns_after!r}"
    )


def _iter_connections(cc):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_connections(**kwargs)
        yield from resp.get("Connections", [])
        token = resp.get("NextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
