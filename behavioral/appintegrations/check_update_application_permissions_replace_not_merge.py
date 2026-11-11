"""update-application-permissions-replace-not-merge."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-application-permissions-replace-not-merge"
GROUP = "state"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplication's Permissions list fully replaces the prior list rather than merging with it."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-app-replace-")
    namespace = ctx.unique_name("sim2real-ns-replace-")

    created = appi.create_application(
        Name=name,
        Namespace=namespace,
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/replace"}
        },
        Permissions=["sim2real.GetApplication", "sim2real.ListApplications"],
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: appi.delete_application(Arn=arn))

    before = appi.get_application(Arn=arn)
    assert sorted(before["Permissions"]) == sorted(
        ["sim2real.GetApplication", "sim2real.ListApplications"]
    ), f"expected the two created permissions, got {before['Permissions']!r}"

    appi.update_application(Arn=arn, Permissions=["sim2real.UpdateApplication"])

    after = appi.get_application(Arn=arn)
    assert after["Permissions"] == ["sim2real.UpdateApplication"], (
        f"expected UpdateApplication's disjoint list to fully replace the prior "
        f"permissions, got {after['Permissions']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
