"""update-hypervisor-persists-new-host."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-hypervisor-persists-new-host"
GROUP = "state"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateHypervisor with a new Host persists: a subsequent GetHypervisor reflects the
    updated value, not the original one, and a field not named in the update (Name) survives
    the partial update untouched."""
    bg = ctx.client("backup-gateway")
    name = ctx.unique_name("sim2real-bgw-")
    host_1 = f"{ctx.unique_name('sim2real-bgw-host1-')}.example.com"
    arn = _create_hypervisor(ctx, host=host_1, name=name)

    before = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]
    assert before["Host"] == host_1, f"expected freshly-imported Host {host_1!r}, got {before['Host']!r}"
    assert before["Name"] == name, f"expected freshly-imported Name {name!r}, got {before['Name']!r}"

    host_2 = f"{ctx.unique_name('sim2real-bgw-host2-')}.example.com"
    bg.update_hypervisor(HypervisorArn=arn, Host=host_2)

    got = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]
    assert got["Host"] == host_2, f"expected updated Host {host_2!r}, got {got['Host']!r}"
    assert got["Host"] != host_1, f"stale Host {host_1!r} still reported after update to {host_2!r}"
    assert got["Name"] == name, (
        f"UpdateHypervisor with only Host set must leave Name untouched: "
        f"expected {name!r}, got {got['Name']!r}"
    )


def _create_hypervisor(ctx, host=None, name=None):
    bg = ctx.client("backup-gateway")
    kwargs = {
        "Name": name or ctx.unique_name("sim2real-bgw-"),
        "Host": host or f"{ctx.unique_name('sim2real-bgw-host-')}.example.com",
        "Username": "sim2real-user",
        "Password": "Sim2Real-Passw0rd!",
        "Tags": [{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    }
    arn = bg.import_hypervisor_configuration(**kwargs)["HypervisorArn"]

    def _cleanup():
        try:
            bg.delete_hypervisor(HypervisorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
