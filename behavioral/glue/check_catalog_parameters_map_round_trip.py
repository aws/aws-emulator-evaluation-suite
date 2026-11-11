"""catalog-parameters-map-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "catalog-parameters-map-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDatabase returns the Name and the exact Parameters map that CreateDatabase set."""
    glue = ctx.client("glue")

    name = ctx.unique_name("sim2real-db-")
    parameters = {
        "owner": "sim2real",
        "unicode": "válüe-日本語-🎯",
        "empty-value": "",
        "numeric-looking": "12345",
        "with.dots.and-dashes": "still-a-value",
    }

    glue.create_database(
        DatabaseInput={"Name": name, "Description": "sim2real fidelity test database", "Parameters": parameters},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))

    fetched = glue.get_database(Name=name)["Database"]
    assert fetched["Name"] == name, f"expected database Name {name!r}, got {fetched['Name']!r}"
    assert fetched["Parameters"] == parameters, (
        f"Parameters mismatch: expected {parameters!r}, got {fetched['Parameters']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
