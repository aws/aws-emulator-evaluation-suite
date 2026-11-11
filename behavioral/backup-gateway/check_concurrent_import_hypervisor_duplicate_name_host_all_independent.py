"""concurrent-import-hypervisor-duplicate-name-host-all-independent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-import-hypervisor-duplicate-name-host-all-independent"
GROUP = "concurrency"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportHypervisorConfiguration enforces no uniqueness on Name or Host: concurrent imports of
    the identical Name+Host pair all succeed, each with its own HypervisorArn (no conflict, no merge)."""
    bg = ctx.client("backup-gateway")
    host = f"{ctx.unique_name('sim2real-bgw-race-')}.example.com"
    name = ctx.unique_name("sim2real-bgw-race-")
    racers = 5

    def _attempt(i: int):
        return bg.import_hypervisor_configuration(
            Name=name,
            Host=host,
            Username="sim2real-user",
            Password="Sim2Real-Passw0rd!",
            Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
        )["HypervisorArn"]

    with ThreadPoolExecutor(max_workers=racers) as pool:
        arns = list(pool.map(_attempt, range(racers)))

    for arn in arns:
        ctx.on_cleanup(lambda a=arn: _safe_delete(bg, a))

    assert len(arns) == racers, f"expected {racers} results from {racers} racers, got {len(arns)}"
    assert len(set(arns)) == racers, f"expected {racers} independent ARNs, got collisions: {arns}"

    for arn in arns:
        got = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]
        assert got["Name"] == name, f"arn {arn}: expected Name {name!r}, got {got['Name']!r}"
        assert got["Host"] == host, f"arn {arn}: expected Host {host!r}, got {got['Host']!r}"


def _safe_delete(bg, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bg.delete_hypervisor(HypervisorArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

