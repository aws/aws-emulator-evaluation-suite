"""create-component-supported-os-versions-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-component-supported-os-versions-roundtrip"
GROUP = "crud-roundtrip"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComponent persists supportedOsVersions and changeDescription, visible via GetComponent."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    doc = (
        f"name: {name}\n"
        "description: os-version-scoped component\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )
    os_versions = ["Amazon Linux 2", "Amazon Linux 2023"]
    change_description = "initial release for AL2/AL2023"

    resp = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=doc,
        supportedOsVersions=os_versions,
        changeDescription=change_description,
        clientToken=str(uuid.uuid4()),
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))

    got = ib.get_component(componentBuildVersionArn=arn)["component"]
    assert sorted(got["supportedOsVersions"]) == sorted(os_versions), (
        f"expected supportedOsVersions {sorted(os_versions)!r}, got {sorted(got['supportedOsVersions'])!r}"
    )
    assert got["changeDescription"] == change_description, (
        f"expected changeDescription {change_description!r}, got {got['changeDescription']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
