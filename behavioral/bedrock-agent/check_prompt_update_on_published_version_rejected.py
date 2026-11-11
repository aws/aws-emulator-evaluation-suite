"""prompt-update-on-published-version-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prompt-update-on-published-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrompt with a numbered-version identifier succeeds and updates DRAFT: the numbered version
    keeps its text, and DRAFT takes the new text."""
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-prompt-")

    def _variant(text: str) -> dict:
        return {
            "name": "default",
            "templateType": "TEXT",
            "templateConfiguration": {"text": {"text": text}},
        }

    created_prompt = bedrock_agent.create_prompt(
        name=name, defaultVariant="default", variants=[_variant("frozen text")]
    )
    prompt_id = created_prompt["id"]
    prompt_arn = created_prompt["arn"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_prompt(promptIdentifier=prompt_id))

    versioned = bedrock_agent.create_prompt_version(promptIdentifier=prompt_id)
    version_number = versioned["version"]
    # A plain 10-char promptIdentifier never accepts a ":<version>" suffix (only the ARN form
    # does) -- so a numbered-version identifier must be built from the ARN, not the bare id.
    versioned_identifier = f"{prompt_arn}:{version_number}"

    # UpdatePrompt with a numbered-version identifier succeeds and retargets DRAFT, so a target
    # that rejects it (ConflictException/ValidationException) diverges from the contract.
    resp = bedrock_agent.update_prompt(
        promptIdentifier=versioned_identifier,
        name=name,
        defaultVariant="default",
        variants=[_variant("attempted mutation")],
    )
    assert resp["version"] == "DRAFT", resp["version"]

    still_frozen_by_arn = bedrock_agent.get_prompt(promptIdentifier=versioned_identifier)
    assert still_frozen_by_arn["variants"][0]["templateConfiguration"]["text"]["text"] == "frozen text", (
        "reading back through the exact identifier form used in the mutation attempt must still "
        "show the frozen numbered snapshot, not the mutation"
    )

    still_frozen = bedrock_agent.get_prompt(promptIdentifier=prompt_id, promptVersion=version_number)
    assert still_frozen["variants"][0]["templateConfiguration"]["text"]["text"] == "frozen text", (
        "the numbered prompt version's content must never be mutated by UpdatePrompt, regardless of "
        "which identifier form was used to address the request"
    )

    updated_draft = bedrock_agent.update_prompt(
        promptIdentifier=prompt_id,
        name=name,
        defaultVariant="default",
        variants=[_variant("draft is mutable")],
    )
    assert updated_draft["version"] == "DRAFT"
    draft_now = bedrock_agent.get_prompt(promptIdentifier=prompt_id)
    assert draft_now["variants"][0]["templateConfiguration"]["text"]["text"] == "draft is mutable"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
