"""update-application-persists-description-and-permissions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-application-persists-description-and-permissions"
GROUP = "state"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplication persists a new Description and Permissions list, visible via GetApplication."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-app-upd-")
    namespace = ctx.unique_name("sim2real-ns-upd-")

    created = appi.create_application(
        Name=name,
        Namespace=namespace,
        Description="before-update",
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/upd"}
        },
        Permissions=["sim2real.GetApplication"],
        Tags={"sim2real": "appintegrations-behavioral"},
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: appi.delete_application(Arn=arn))

    appi.update_application(
        Arn=arn,
        Description="after-update",
        Permissions=["sim2real.GetApplication", "sim2real.ListApplications"],
    )

    got = appi.get_application(Arn=arn)
    assert got["Description"] == "after-update", (
        f"expected Description 'after-update' after UpdateApplication, got {got.get('Description')!r}"
    )
    expected_permissions = sorted(["sim2real.GetApplication", "sim2real.ListApplications"])
    assert sorted(got["Permissions"]) == expected_permissions, (
        f"expected Permissions {expected_permissions} after UpdateApplication, got {got.get('Permissions')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
