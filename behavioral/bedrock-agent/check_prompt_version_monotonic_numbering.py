"""prompt-version-monotonic-numbering."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prompt-version-monotonic-numbering"
GROUP = "ordering"
SERVICES = ["bedrock-agent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated CreatePromptVersion calls on the same prompt yield strictly increasing,
    contiguous version numbers, and ListPrompts(promptIdentifier=...) reports the exact
    same set of versions."""
    bedrock = ctx.client("bedrock-agent")

    prompt = bedrock.create_prompt(
        name=ctx.unique_name("sim2real-prompt-"),
        variants=[
            {
                "name": "variant-1",
                "templateType": "TEXT",
                "templateConfiguration": {"text": {"text": "Summarize: {{input}}"}},
            }
        ],
        defaultVariant="variant-1",
        tags={"sim2real": CHECK},
    )
    prompt_id = prompt["id"]
    ctx.on_cleanup(lambda: bedrock.delete_prompt(promptIdentifier=prompt_id))

    created_versions = []
    for _ in range(4):
        resp = bedrock.create_prompt_version(promptIdentifier=prompt_id)
        created_versions.append(resp["version"])

    numeric_versions = [int(v) for v in created_versions]
    assert numeric_versions == sorted(numeric_versions), f"versions not increasing: {created_versions}"
    assert len(set(numeric_versions)) == 4, f"duplicate version numbers: {created_versions}"
    assert numeric_versions == list(range(numeric_versions[0], numeric_versions[0] + 4)), (
        f"versions are not a contiguous increasing sequence: {created_versions}"
    )

    listed = bedrock.list_prompts(promptIdentifier=prompt_id)["promptSummaries"]
    listed_numeric = sorted(int(v["version"]) for v in listed if v["version"] != "DRAFT")
    assert listed_numeric == numeric_versions, (
        f"ListPrompts {listed_numeric} does not match created versions {numeric_versions}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
