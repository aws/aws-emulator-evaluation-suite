"""delete-terminology-then-get-returns-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-terminology-then-get-returns-not-found"
GROUP = "error-semantics"
SERVICES = ["translate"]


def _expect_not_found(fn, what: str, expected_message: str) -> None:
    """Call fn(); it must raise ResourceNotFoundException with expected_message, never return successfully."""
    try:
        fn()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"{what}: expected ResourceNotFoundException, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == expected_message, f"{what}: expected message {expected_message!r}, got {message!r}"
        return
    raise AssertionError(f"{what}: expected ResourceNotFoundException, but the call succeeded")


def _delete_terminology_ignore_missing(translate, name: str) -> None:
    """Teardown delete that tolerates a terminology the check already removed."""
    try:
        translate.delete_terminology(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteTerminology, GetTerminology and a second DeleteTerminology fail with
    ResourceNotFoundException and the exact message, and the freed name imports again and reads back with
    TermCount 1."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-")
    body = {"File": b"en,es\nHello,Hola\n", "Format": "CSV"}

    translate.import_terminology(Name=name, MergeStrategy="OVERWRITE", TerminologyData=body)
    ctx.on_cleanup(lambda: _delete_terminology_ignore_missing(translate, name))

    # sanity: the resource is visible before delete (positive control)
    before = translate.get_terminology(Name=name)["TerminologyProperties"]
    assert before["Name"] == name, f"expected the created terminology to be visible, got {before}"

    translate.delete_terminology(Name=name)

    _expect_not_found(
        lambda: translate.get_terminology(Name=name),
        "GetTerminology after delete",
        f"The Terminology for {ctx.account} {name} was not found",
    )
    _expect_not_found(
        lambda: translate.delete_terminology(Name=name),
        "DeleteTerminology on an already-deleted name",
        f"The TerminologyMetadata for {ctx.account} {name} was not found",
    )

    # the freed name is reusable, and the recreated resource is independently readable
    recreate_props = translate.import_terminology(
        Name=name, MergeStrategy="OVERWRITE", TerminologyData=body
    )["TerminologyProperties"]
    ctx.on_cleanup(lambda: _delete_terminology_ignore_missing(translate, name))
    assert recreate_props["Name"] == name, (
        f"expected the freed name to be reusable, got {recreate_props}"
    )

    reread_props = translate.get_terminology(Name=name)["TerminologyProperties"]
    assert reread_props["Name"] == name and reread_props["TermCount"] == 1, (
        f"expected the recreated terminology to be independently readable, got {reread_props}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
