"""concurrent-create-connections-produce-unique-arns."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-connections-produce-unique-arns"
GROUP = "concurrency"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateConnection calls return a distinct ARN for every connection, and each reads back
    with its own name and ARN."""
    cc = ctx.client("codeconnections")
    names = [ctx.unique_name(f"sim2real-cc{i}-")[:32] for i in range(8)]

    def _create(name: str) -> str:
        return cc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        arns = list(pool.map(_create, names))

    for arn in arns:
        ctx.on_cleanup(lambda a=arn: cc.delete_connection(ConnectionArn=a))

    assert len(arns) == len(names), f"expected {len(names)} ARNs, got {len(arns)}"
    assert len(set(arns)) == len(arns), "duplicate ARN produced under concurrent creation"

    for name, arn in zip(names, arns):
        got = cc.get_connection(ConnectionArn=arn)["Connection"]
        assert got["ConnectionName"] == name, f"expected name {name!r}, got {got['ConnectionName']!r}"
        assert got["ConnectionArn"] == arn, f"expected arn {arn!r}, got {got['ConnectionArn']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
