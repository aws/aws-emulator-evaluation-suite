"""custom-entity-type-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-entity-type-lifecycle"
GROUP = 'custom-entity-type'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """custom_entity_type create -> get -> list -> batch-get -> delete."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-cet-")
    regex = r"[0-9]{3}-[0-9]{2}-[0-9]{4}"
    context_words = ["identifier", "reference"]
    glue.create_custom_entity_type(
        Name=name,
        RegexString=regex,
        ContextWords=context_words,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_custom_entity_type(Name=name))

    cet = glue.get_custom_entity_type(Name=name)
    assert cet["Name"] == name, f"expected Name {name!r}, got {cet.get('Name')!r}"
    assert cet["RegexString"] == regex, f"regex not persisted: {cet}"
    assert cet["ContextWords"] == context_words, f"context words lost: {cet}"

    names = {c["Name"] for c in glue.list_custom_entity_types()["CustomEntityTypes"]}
    assert name in names, "custom entity type missing from ListCustomEntityTypes"

    batch = glue.batch_get_custom_entity_types(Names=[name, "does-not-exist-cet"])
    batch_names = [c["Name"] for c in batch["CustomEntityTypes"]]
    assert batch_names == [name], f"expected batch-get to return [{name!r}], got {batch_names}"
    assert batch["CustomEntityTypesNotFound"] == ["does-not-exist-cet"], (
        f"unknown entity type must be reported as not found: {batch}"
    )

    glue.delete_custom_entity_type(Name=name)
    try:
        glue.get_custom_entity_type(Name=name)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after DeleteCustomEntityType, got {code}"
    )
    assert message == f"An existing Custom Entity Type: {cet['Name']} cannot be found for Account Id {ctx.account}", (
        f"expected the exact EntityNotFoundException message AWS returns, got {message!r}"
    )

    # A mutation on the now-dead id must also fail, not silently no-op.
    try:
        glue.delete_custom_entity_type(Name=name)
        second_delete_code = None
        second_delete_message = None
    except ClientError as exc:
        second_delete_code = exc.response.get("Error", {}).get("Code")
        second_delete_message = exc.response.get("Error", {}).get("Message")
    assert second_delete_code == "EntityNotFoundException", (
        f"expected a second delete of the same name to fail with EntityNotFoundException, "
        f"got {second_delete_code}"
    )
    assert second_delete_message == f"An existing Custom Entity Type: {cet['Name']} cannot be found for Account Id {ctx.account}", (
        f"expected the exact EntityNotFoundException message AWS returns, got {second_delete_message!r}"
    )

    # The identifier must be reusable once freed.
    glue.create_custom_entity_type(
        Name=name,
        RegexString=regex,
        ContextWords=context_words,
        Tags={"sim2real": CHECK},
    )
    recreated = glue.get_custom_entity_type(Name=name)
    assert recreated["Name"] == name, f"deleted custom entity type name must be reusable, got {recreated}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
