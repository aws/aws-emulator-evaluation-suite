"""update-prompt-version-qualified-identifier-redirects-to-draft."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-prompt-version-qualified-identifier-redirects-to-draft"
GROUP = "server-side"
SERVICES = ["bedrock-agent"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrompt with a version-qualified identifier updates DRAFT and leaves the numbered version
    unchanged; GetPrompt of a never-created version gets ResourceNotFoundException with the exact
    message, and UpdatePrompt qualified with it also updates DRAFT without creating it."""
    bedrock = ctx.client("bedrock-agent")

    original_name = ctx.unique_name("sim2real-prompt-immut-")
    prompt = bedrock.create_prompt(
        name=original_name,
        tags={"sim2real": "audit"},
        variants=[{
            "name": "v1",
            "templateType": "TEXT",
            "templateConfiguration": {"text": {"text": "Hello, {{name}}!", "inputVariables": [{"name": "name"}]}},
        }],
    )
    prompt_id = prompt["id"]
    prompt_arn = prompt["arn"]
    ctx.on_cleanup(lambda: bedrock.delete_prompt(promptIdentifier=prompt_id))

    version_resp = bedrock.create_prompt_version(promptIdentifier=prompt_id)
    numbered_version = version_resp["version"]
    assert numbered_version != "DRAFT", f"expected a numbered version, got {numbered_version!r}"
    versioned_identifier = f"{prompt_arn}:{numbered_version}"

    # Positive control: updating the DRAFT (unqualified identifier) works.
    draft_new_name = ctx.unique_name("sim2real-prompt-immut-updated-")
    bedrock.update_prompt(promptIdentifier=prompt_id, name=draft_new_name)
    draft_after_update = bedrock.get_prompt(promptIdentifier=prompt_id)
    assert draft_after_update["name"] == draft_new_name, (
        f"expected DRAFT name {draft_new_name!r} after unqualified UpdatePrompt, got "
        f"{draft_after_update['name']!r}"
    )

    # Calling UpdatePrompt with a version-qualified identifier does NOT raise -- per the
    # documented contract, "when you update a prompt, the version updated is the DRAFT
    # version" -- so this call is silently redirected to the DRAFT rather than mutating
    # the immutable numbered snapshot.
    redirected_name = ctx.unique_name("sim2real-prompt-immut-redirected-")
    bedrock.update_prompt(promptIdentifier=versioned_identifier, name=redirected_name)

    draft_after_redirect = bedrock.get_prompt(promptIdentifier=prompt_id)
    assert draft_after_redirect["name"] == redirected_name, (
        "expected the version-qualified UpdatePrompt call to be redirected to DRAFT"
    )

    # The numbered version's stored name must remain exactly what CreatePromptVersion
    # captured -- untouched by either DRAFT update above.
    versioned_after_attempt = bedrock.get_prompt(
        promptIdentifier=prompt_id, promptVersion=numbered_version
    )
    assert versioned_after_attempt["name"] == original_name, (
        f"expected the numbered version's name to stay {original_name!r}, got "
        f"{versioned_after_attempt['name']!r}"
    )

    # Negative/overly-permissive control: GetPrompt on a numbered version that was never
    # created is rejected outright with ResourceNotFoundException.
    unused_version = str(int(numbered_version) + 1)
    get_code, get_message = _error(
        lambda: bedrock.get_prompt(promptIdentifier=prompt_id, promptVersion=unused_version)
    )
    assert get_code == "ResourceNotFoundException", get_code
    assert get_message == (
        "Couldn't perform GetPrompt operation. Failed to retrieve resource type PromptVersion "
        "because it doesn't exist. Check the resource ID and retry your request."
    ), get_message

    # UpdatePrompt qualified with that never-created version is redirected to DRAFT as well:
    # the qualifier is not resolved, so the write lands on DRAFT and no version materializes.
    unused_qualified_name = ctx.unique_name("sim2real-prompt-immut-unused-")
    unused_update = bedrock.update_prompt(
        promptIdentifier=f"{prompt_arn}:{unused_version}", name=unused_qualified_name
    )
    assert unused_update["version"] == "DRAFT", unused_update["version"]
    assert bedrock.get_prompt(promptIdentifier=prompt_id)["name"] == unused_qualified_name
    still_missing_code, still_missing_message = _error(
        lambda: bedrock.get_prompt(promptIdentifier=prompt_id, promptVersion=unused_version)
    )
    assert still_missing_code == "ResourceNotFoundException", still_missing_code
    assert still_missing_message == get_message, still_missing_message


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

