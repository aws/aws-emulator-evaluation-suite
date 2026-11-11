"""import-component-get-roundtrip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-component-get-roundtrip"
GROUP = "crud-roundtrip"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportComponent wraps a raw shell script into a BUILD-type component, visible via GetComponent."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-import-comp-")
    script = "echo hello-from-imported-component\n"

    resp = ib.import_component(
        name=name,
        semanticVersion="1.0.0",
        type="BUILD",
        format="SHELL",
        platform="Linux",
        data=script,
        clientToken=str(uuid.uuid4()),
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: _delete_if_present(ib, arn))

    got = ib.get_component(componentBuildVersionArn=arn)["component"]
    assert got["name"] == name, f"expected name {name!r}, got {got.get('name')!r}"
    assert got["type"] == "BUILD", f"expected type BUILD, got {got.get('type')!r}"
    assert got["platform"] == "Linux", f"expected platform Linux, got {got.get('platform')!r}"
    assert "hello-from-imported-component" in got["data"], (
        f"expected imported script content in component data, got {got.get('data')!r}"
    )

    ib.delete_component(componentBuildVersionArn=arn)
    try:
        ib.get_component(componentBuildVersionArn=arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException after delete, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        expected = f"The following required resource 'Component' cannot be found: '{arn}'."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("expected GetComponent to fail after DeleteComponent, but it succeeded")


def _delete_if_present(ib, arn: str) -> None:
    try:
        ib.delete_component(componentBuildVersionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
