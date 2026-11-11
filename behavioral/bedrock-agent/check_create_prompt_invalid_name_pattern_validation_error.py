"""create-prompt-invalid-name-pattern-validation-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-prompt-invalid-name-pattern-validation-error"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]

# Exercises a server-side (not botocore client-side) validation boundary on Prompt: the
# `name` pattern `([0-9a-zA-Z][_-]?){1,100}` is a regex constraint that botocore's param validator
# does not enforce locally (unlike length constraints, which raise ParamValidationError before any
# request is sent) -- so a name containing spaces/punctuation actually reaches the wire and AWS
# itself must reject it with ValidationException.


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePrompt rejects a name that violates the documented pattern with ValidationException,
    and the rejected prompt never shows up in ListPrompts; a pattern-conformant name succeeds."""
    bedrock_agent = ctx.client("bedrock-agent")
    invalid_name = "not a valid prompt name!"

    code, message = _error(
        lambda: bedrock_agent.create_prompt(
            name=invalid_name,
            defaultVariant="default",
            variants=[
                {"name": "default", "templateType": "TEXT", "templateConfiguration": {"text": {"text": "hello"}}}
            ],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        f"1 validation error detected: Value '{invalid_name}' at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ([0-9a-zA-Z][_-]?){1,100}"
    ), message

    listing = bedrock_agent.list_prompts()["promptSummaries"]
    assert all(p["name"] != invalid_name for p in listing), (
        f"rejected prompt {invalid_name!r} should not appear in ListPrompts"
    )

    valid_name = ctx.unique_name("sim2real-prompt-")
    created = bedrock_agent.create_prompt(
        name=valid_name,
        defaultVariant="default",
        variants=[
            {"name": "default", "templateType": "TEXT", "templateConfiguration": {"text": {"text": "hello"}}}
        ],
        tags={"sim2real": CHECK},
    )
    prompt_id = created["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_prompt(promptIdentifier=prompt_id))

    # Terminal read is independent of the mutating CreatePrompt call: GetPrompt at the
    # destination must show the pattern-conformant prompt actually landed.
    fetched = bedrock_agent.get_prompt(promptIdentifier=prompt_id)
    assert fetched["name"] == valid_name, f"expected GetPrompt name {valid_name!r}, got {fetched['name']!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
