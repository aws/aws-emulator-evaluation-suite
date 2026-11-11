"""prompt-version-snapshots-draft-immutably."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prompt-version-snapshots-draft-immutably"
GROUP = "versioning"
SERVICES = ["bedrock-agent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePromptVersion freezes the DRAFT content; later DRAFT edits do not leak into the numbered version."""
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-prompt-")

    def _variant(text: str) -> dict:
        return {
            "name": "default",
            "templateType": "TEXT",
            "templateConfiguration": {"text": {"text": text}},
        }

    created = bedrock_agent.create_prompt(
        name=name,
        defaultVariant="default",
        variants=[_variant("Original draft text v1")],
        tags={"sim2real": CHECK},
    )
    prompt_id = created["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_prompt(promptIdentifier=prompt_id))
    assert created["version"] == "DRAFT", f"expected new prompt at DRAFT, got {created['version']!r}"

    versioned = bedrock_agent.create_prompt_version(promptIdentifier=prompt_id)
    version_number = versioned["version"]
    assert version_number != "DRAFT", "CreatePromptVersion must snapshot to a numbered version, not DRAFT"
    snapshot_text = versioned["variants"][0]["templateConfiguration"]["text"]["text"]
    assert snapshot_text == "Original draft text v1", (
        f"expected CreatePromptVersion's own response to echo the DRAFT content it snapshotted, got {snapshot_text!r}"
    )

    bedrock_agent.update_prompt(
        promptIdentifier=prompt_id,
        name=name,
        defaultVariant="default",
        variants=[_variant("Mutated draft text v2")],
    )

    draft_now = bedrock_agent.get_prompt(promptIdentifier=prompt_id)
    draft_text = draft_now["variants"][0]["templateConfiguration"]["text"]["text"]
    assert draft_text == "Mutated draft text v2", (
        f"expected DRAFT to reflect the UpdatePrompt just issued, got {draft_text!r}"
    )

    frozen = bedrock_agent.get_prompt(promptIdentifier=prompt_id, promptVersion=version_number)
    frozen_text = frozen["variants"][0]["templateConfiguration"]["text"]["text"]
    assert frozen_text == "Original draft text v1", (
        f"numbered prompt version must remain frozen after later DRAFT edits, got {frozen_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
