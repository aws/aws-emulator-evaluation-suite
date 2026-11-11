"""create-application-get-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-application-get-roundtrip"
GROUP = "data-plane"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication persists Name/Namespace/Description/ApplicationSourceConfig, retrievable via GetApplication."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-app-")
    namespace = ctx.unique_name("sim2real-ns-")
    access_url = "https://example.com/sim2real-app"
    approved_origins = ["https://example.com"]

    created = appi.create_application(
        Name=name,
        Namespace=namespace,
        Description="sim2real roundtrip test application",
        ApplicationSourceConfig={
            "ExternalUrlConfig": {
                "AccessUrl": access_url,
                "ApprovedOrigins": approved_origins,
            }
        },
        Tags={"sim2real": "appintegrations-behavioral"},
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: appi.delete_application(Arn=arn))

    assert created["Id"], f"expected a non-empty Id from CreateApplication, got {created.get('Id')!r}"
    assert arn, f"expected a non-empty Arn from CreateApplication, got {arn!r}"

    got = appi.get_application(Arn=arn)
    assert got["Name"] == name, f"expected persisted Name {name!r}, got {got['Name']!r}"
    assert got["Namespace"] == namespace, (
        f"expected persisted Namespace {namespace!r}, got {got['Namespace']!r}"
    )
    assert got["Description"] == "sim2real roundtrip test application", (
        f"expected persisted Description, got {got['Description']!r}"
    )
    src_cfg = got["ApplicationSourceConfig"]["ExternalUrlConfig"]
    assert src_cfg["AccessUrl"] == access_url, (
        f"expected persisted AccessUrl {access_url!r}, got {src_cfg['AccessUrl']!r}"
    )
    assert src_cfg["ApprovedOrigins"] == approved_origins, (
        f"expected persisted ApprovedOrigins {approved_origins!r}, got {src_cfg['ApprovedOrigins']!r}"
    )
    assert got["Arn"] == arn, f"expected GetApplication Arn {arn!r}, got {got['Arn']!r}"
    assert got["Id"] == created["Id"], (
        f"expected GetApplication Id {created['Id']!r}, got {got['Id']!r}"
    )
    assert "CreatedTime" in got, f"expected CreatedTime in GetApplication response, got keys {list(got)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
