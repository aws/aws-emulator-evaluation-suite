"""athena-workgroup-create-default-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-workgroup-create-default-state"
GROUP = "state"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkGroup produces a workgroup whose initial State is ENABLED with default config."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(
        Name=name,
        Description="behavioral check workgroup",
        Configuration={
            "EnforceWorkGroupConfiguration": False,
            "PublishCloudWatchMetricsEnabled": True,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    wg = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert wg["Name"] == name, f"expected Name {name!r}, got {wg['Name']!r}"
    assert wg["State"] == "ENABLED", f"expected State ENABLED, got {wg['State']!r}"
    assert wg["Description"] == "behavioral check workgroup", (
        f"expected Description 'behavioral check workgroup', got {wg['Description']!r}"
    )
    cfg = wg["Configuration"]
    assert cfg["EnforceWorkGroupConfiguration"] is False, (
        f"expected EnforceWorkGroupConfiguration False, got {cfg['EnforceWorkGroupConfiguration']!r}"
    )
    assert cfg["PublishCloudWatchMetricsEnabled"] is True, (
        f"expected PublishCloudWatchMetricsEnabled True, got {cfg['PublishCloudWatchMetricsEnabled']!r}"
    )

    names = [w["Name"] for w in athena.list_work_groups()["WorkGroups"]]
    assert name in names, f"expected {name!r} in ListWorkGroups, got {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
