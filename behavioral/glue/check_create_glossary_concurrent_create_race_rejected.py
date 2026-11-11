"""create-glossary-concurrent-create-race-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-glossary-concurrent-create-race-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateGlossary calls for the same Name resolve to exactly one
    winner; the loser gets AlreadyExistsException, never a second, independent glossary
    silently created under the same name."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-glue-glossary-race-")

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(glue.create_glossary, Name=name, Description="from-caller-A")
        f2 = pool.submit(glue.create_glossary, Name=name, Description="from-caller-B")
        outcomes = []
        for fut in (f1, f2):
            try:
                outcomes.append(("success", fut.result()))
            except ClientError as e:
                outcomes.append((e.response["Error"]["Code"], e.response["Error"].get("Message")))

    successes = [o for o in outcomes if o[0] == "success"]
    failures = [o for o in outcomes if o[0] != "success"]
    assert len(successes) == 1, f"expected exactly one winner, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one loser, got {outcomes}"
    assert failures[0][0] == "AlreadyExistsException", (
        f"expected AlreadyExistsException for the loser, got {failures[0][0]}"
    )
    # AWS returns the JSON error body as this refusal's message.
    expected = f"{{\"Message\":\"A glossary with name '{name}' already exists.\"}}"
    assert failures[0][1] == expected, f"expected {expected!r}, got {failures[0][1]!r}"

    winner_id = successes[0][1]["Id"]
    winner_desc = successes[0][1]["Description"]
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_glossary(Identifier=winner_id)))

    # Effect: exactly one glossary exists under that name/id, and it carries the
    # winning racer's own description -- not a merge of both callers' writes.
    glossary = glue.get_glossary(Identifier=winner_id)
    assert glossary["Name"] == name and glossary["Description"] == winner_desc, (
        f"expected winner's own write ({name!r}, {winner_desc!r}), got {glossary}"
    )

    # Positive control (same file): a distinct name still creates cleanly, proving
    # the account/credentials are otherwise healthy for CreateGlossary.
    control_name = ctx.unique_name("sim2real-glue-glossary-ctrl-")
    control_id = glue.create_glossary(Name=control_name)["Id"]
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_glossary(Identifier=control_id)))
    control = glue.get_glossary(Identifier=control_id)
    assert control["Name"] == control_name, (
        f"expected control glossary name {control_name!r}, got {control}"
    )


# ===== helpers =====
def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
