"""prompt-empty-vs-absent-field-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prompt-empty-vs-absent-field-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-agent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A prompt variant with an explicit empty-string metadata value round-trips as a
    present entry with value "", distinguishable from a variant where the metadata
    field was never supplied at all (which stays entirely absent from GetPrompt)."""
    bedrock = ctx.client("bedrock-agent")

    variant_with_explicit_empty = {
        "name": "variant1",
        "templateType": "TEXT",
        "templateConfiguration": {"text": {"text": "Hello there, world."}},
        "metadata": [{"key": "label", "value": ""}],
    }
    variant_without_metadata = {
        "name": "variant1",
        "templateType": "TEXT",
        "templateConfiguration": {"text": {"text": "Hello there, world."}},
    }

    prompt_explicit = bedrock.create_prompt(
        name=ctx.unique_name("sim2real-prompt-explicit-"),
        variants=[variant_with_explicit_empty],
        tags={"sim2real": "prompt-empty-vs-absent-field-preserved"},
    )
    ctx.on_cleanup(lambda: bedrock.delete_prompt(promptIdentifier=prompt_explicit["id"]))

    prompt_absent = bedrock.create_prompt(
        name=ctx.unique_name("sim2real-prompt-absent-"),
        variants=[variant_without_metadata],
        tags={"sim2real": "prompt-empty-vs-absent-field-preserved"},
    )
    ctx.on_cleanup(lambda: bedrock.delete_prompt(promptIdentifier=prompt_absent["id"]))

    got_explicit = bedrock.get_prompt(promptIdentifier=prompt_explicit["id"])
    got_absent = bedrock.get_prompt(promptIdentifier=prompt_absent["id"])

    explicit_variant = got_explicit["variants"][0]
    absent_variant = got_absent["variants"][0]

    assert explicit_variant.get("metadata") == [{"key": "label", "value": ""}], (
        f"expected metadata [{{'key': 'label', 'value': ''}}], got {explicit_variant.get('metadata')!r}"
    )
    assert "metadata" not in absent_variant, (
        f"expected metadata to be entirely absent, got {absent_variant.get('metadata')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
