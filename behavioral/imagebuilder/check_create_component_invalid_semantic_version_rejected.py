"""create-component-invalid-semantic-version-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-component-invalid-semantic-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateComponent rejects a semanticVersion node value that exceeds the 2^30-1 upper bound, and never creates the component."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    doc = (
        f"name: {name}\n"
        "description: invalid version test\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )

    code, msg = _error(
        lambda: ib.create_component(
            name=name,
            semanticVersion="9999999999.0.0",  # syntactically valid but exceeds the 2^30-1 node bound
            platform="Linux",
            data=doc,
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected = (
        "The value supplied for parameter 'semanticVersion' is not valid. "
        "The supplied semantic version does not follow the required format."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: no component build version was created under this name
    listed = ib.list_components(owner="Self", filters=[{"name": "name", "values": [name]}])["componentVersionList"]
    assert listed == [], f"expected no component versions under {name!r}, found {listed!r}"

    # positive control: a well-formed semanticVersion succeeds
    created = ib.create_component(
        name=name, semanticVersion="1.0.0", platform="Linux", data=doc, clientToken=str(uuid.uuid4())
    )
    arn = created["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))

    # terminal independent read: the positive control is real, not merely un-rejected
    got = ib.get_component(componentBuildVersionArn=arn)["component"]
    assert got["arn"] == arn, f"expected get_component to reflect {arn!r}, got {got.get('arn')!r}"
    assert got["name"] == name, f"expected component name {name!r}, got {got.get('name')!r}"
    assert got["version"] == "1.0.0", f"expected version '1.0.0', got {got.get('version')!r}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
