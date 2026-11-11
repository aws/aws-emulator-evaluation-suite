"""database-update-description."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "database-update-description"
GROUP = 'database'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """update_database replaces the whole DatabaseInput, not merges it: a field present at
    create but omitted from the update disappears, while a field the update does carry is
    visible on an independent get."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(
        DatabaseInput={"Name": name, "Description": "original", "Parameters": {"marker": "initial"}}
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))

    glue.update_database(
        Name=name,
        DatabaseInput={"Name": name, "Description": "updated-description"},
    )

    db = glue.get_database(Name=name)["Database"]
    assert db["Description"] == "updated-description", db.get("Description")
    assert "marker" not in db.get("Parameters", {}), db.get("Parameters")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
