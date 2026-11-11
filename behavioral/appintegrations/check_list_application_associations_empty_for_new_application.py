"""list-application-associations-empty-for-new-application."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-application-associations-empty-for-new-application"
GROUP = "state"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created Application (never linked to a client) has zero ApplicationAssociations."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-app-assoc-")
    namespace = ctx.unique_name("sim2real-ns-assoc-")

    created = appi.create_application(
        Name=name,
        Namespace=namespace,
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/assoc"}
        },
        Tags={"sim2real": "appintegrations-behavioral"},
    )
    arn = created["Arn"]
    application_id = created["Id"]
    ctx.on_cleanup(lambda: appi.delete_application(Arn=arn))

    resp = appi.list_application_associations(ApplicationId=application_id)
    assert resp["ApplicationAssociations"] == [], (
        f"expected no associations for a freshly created application, got {resp['ApplicationAssociations']!r}"
    )
    assert "NextToken" not in resp or resp["NextToken"] in (None, ""), (
        f"expected no NextToken on an empty page, got {resp.get('NextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
