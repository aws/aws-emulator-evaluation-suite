"""create-prompt-variant-mismatch-validation-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-prompt-variant-mismatch-validation-error"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePrompt rejects a defaultVariant name that isn't among the supplied variants."""
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-prompt-")
    variant = {
        "name": "actual_variant",
        "templateType": "TEXT",
        "templateConfiguration": {"text": {"text": "hello {{name}}"}},
    }

    code, message = _error(
        lambda: bedrock_agent.create_prompt(
            name=name, defaultVariant="a_name_not_in_variants", variants=[variant]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "Default variant must be present in the variants list. Retry your request with the correct default variant."
    ), message

    listing = bedrock_agent.list_prompts()["promptSummaries"]
    assert all(p["name"] != name for p in listing), f"rejected prompt {name!r} leaked into ListPrompts"

    created = bedrock_agent.create_prompt(
        name=name,
        defaultVariant="actual_variant",
        variants=[variant],
        tags={"sim2real:managed": "true"},
    )
    prompt_id = created["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_prompt(promptIdentifier=prompt_id))

    fetched = bedrock_agent.get_prompt(promptIdentifier=prompt_id)
    assert fetched["defaultVariant"] == "actual_variant", (
        f"expected GetPrompt defaultVariant 'actual_variant', got {fetched.get('defaultVariant')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
