"""op-contract-update-workgroup-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-workgroup-configuration"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkGroup mutates Configuration/Description/State and GetWorkGroup reflects
    the exact new values (not merely "no error")."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")

    athena.create_work_group(
        Name=name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://sim2real-behav-athena-{name}/results/"},
            "EnforceWorkGroupConfiguration": False,
            "PublishCloudWatchMetricsEnabled": False,
            "BytesScannedCutoffPerQuery": 20_000_000,
            "RequesterPaysEnabled": False,
        },
        Description="initial description",
        Tags=[{"Key": "sim2real", "Value": "update-workgroup-configuration-contract"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name))

    before = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert before["State"] == "ENABLED", "new workgroup must default to ENABLED"
    assert before["Configuration"]["EnforceWorkGroupConfiguration"] is False, (
        before["Configuration"]["EnforceWorkGroupConfiguration"]
    )
    assert before["Configuration"]["BytesScannedCutoffPerQuery"] == 20_000_000, (
        before["Configuration"]["BytesScannedCutoffPerQuery"]
    )

    resp = athena.update_work_group(
        WorkGroup=name,
        Description="updated description",
        ConfigurationUpdates={
            "EnforceWorkGroupConfiguration": True,
            "PublishCloudWatchMetricsEnabled": True,
            "BytesScannedCutoffPerQuery": 50_000_000,
            "RequesterPaysEnabled": False,
        },
        State="DISABLED",
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, resp["ResponseMetadata"]

    after = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert after["Description"] == "updated description", after["Description"]
    assert after["State"] == "DISABLED", after["State"]
    cfg = after["Configuration"]
    assert cfg["EnforceWorkGroupConfiguration"] is True, cfg["EnforceWorkGroupConfiguration"]
    assert cfg["PublishCloudWatchMetricsEnabled"] is True, cfg["PublishCloudWatchMetricsEnabled"]
    assert cfg["BytesScannedCutoffPerQuery"] == 50_000_000, cfg["BytesScannedCutoffPerQuery"]
    # OutputLocation set at creation must survive an update that didn't touch ResultConfiguration.
    assert cfg["ResultConfiguration"]["OutputLocation"] == f"s3://sim2real-behav-athena-{name}/results/", (
        cfg["ResultConfiguration"]["OutputLocation"]
    )

    # Toggle State back to ENABLED via a second, independent UpdateWorkGroup call.
    athena.update_work_group(WorkGroup=name, State="ENABLED")
    toggled = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert toggled["State"] == "ENABLED", toggled["State"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
