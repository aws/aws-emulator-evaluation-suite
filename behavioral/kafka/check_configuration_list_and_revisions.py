"""configuration-list-and-revisions."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "configuration-list-and-revisions"
GROUP = 'configuration'
SERVICES = ['kafka']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConfigurations enumerates a newly-created configuration by Arn."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-config-list-")
    resp = msk.create_configuration(
        Name=name,
        ServerProperties=b"num.partitions=1\n",
        KafkaVersions=["3.6.0"],
    )
    arn = resp["Arn"]
    ctx.on_cleanup(lambda _a=arn: msk.delete_configuration(Arn=_a))

    found = []
    next_token = None
    for _ in range(50):
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        page = msk.list_configurations(**kwargs)
        found.extend(page.get("Configurations", []))
        next_token = page.get("NextToken")
        if not next_token:
            break

    matches = [c for c in found if c.get("Arn") == arn]
    assert matches, f"created configuration {arn} not found in ListConfigurations"
    assert matches[0]["Name"] == name, f"expected Name {name!r}, got {matches[0]['Name']!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
