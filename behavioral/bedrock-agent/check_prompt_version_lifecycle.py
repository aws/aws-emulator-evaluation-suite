"""prompt-version-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "prompt-version-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePromptVersion snapshots DRAFT into a numbered version that keeps its text while DRAFT
    changes, and after DeletePrompt both are gone: GetPrompt and UpdatePrompt get
    ResourceNotFoundException with the exact messages."""
    bedrock = ctx.client("bedrock-agent")

    variant = {
        "name": "v1",
        "templateType": "TEXT",
        "templateConfiguration": {
            "text": {
                "text": "Hello {{name}}, how can I help you today?",
                "inputVariables": [{"name": "name"}],
            }
        },
    }
    created = bedrock.create_prompt(
        name=ctx.unique_name("sim2real-prompt-"),
        variants=[variant],
        defaultVariant="v1",
    )
    prompt_id = created["id"]
    prompt_arn = created["arn"]
    assert created["version"] == "DRAFT", f"expected CreatePrompt to start at DRAFT, got {created['version']!r}"
    ctx.on_cleanup(lambda: _best_effort_delete_prompt(bedrock, prompt_id))

    version_resp = bedrock.create_prompt_version(promptIdentifier=prompt_id)
    numbered_version = version_resp["version"]
    assert numbered_version != "DRAFT" and numbered_version.isdigit(), (
        f"expected a numeric snapshot version, got {numbered_version!r}"
    )
    numbered_arn = f"{prompt_arn}:{numbered_version}"

    numbered = bedrock.get_prompt(promptIdentifier=numbered_arn)
    assert numbered["version"] == numbered_version, (
        f"expected GetPrompt on {numbered_arn} to report version={numbered_version!r}, got {numbered['version']!r}"
    )
    assert numbered["variants"][0]["templateConfiguration"]["text"]["text"] == variant[
        "templateConfiguration"
    ]["text"]["text"], "expected the numbered snapshot to carry the variant text present at CreatePromptVersion"

    draft_still = bedrock.get_prompt(promptIdentifier=prompt_id)
    assert draft_still["version"] == "DRAFT", (
        f"expected GetPrompt on the bare id to still report DRAFT, got {draft_still['version']!r}"
    )

    updated_variant = dict(variant)
    updated_variant["templateConfiguration"] = {
        "text": {"text": "Hi {{name}}, what can I do for you?", "inputVariables": [{"name": "name"}]}
    }

    # Empirically, UpdatePrompt accepts a version-qualified identifier syntactically
    # but always mutates the DRAFT (per API docs: "the version updated is the DRAFT
    # version") — the numbered snapshot itself is untouched. Verify that immutability
    # holds via the snapshot's content, not via a rejection error.
    updated = bedrock.update_prompt(
        promptIdentifier=numbered_arn,
        name=created["name"],
        variants=[updated_variant],
        defaultVariant="v1",
    )
    assert updated["version"] == "DRAFT", (
        f"expected UpdatePrompt to always target DRAFT, got version={updated['version']}"
    )
    assert updated["variants"][0]["templateConfiguration"]["text"]["text"] == updated_variant[
        "templateConfiguration"
    ]["text"]["text"], "expected UpdatePrompt's own response to reflect the new variant text"

    # The numbered snapshot remains frozen at its original content despite the update.
    numbered_after = bedrock.get_prompt(promptIdentifier=numbered_arn)
    assert numbered_after["version"] == numbered_version, (
        f"expected the numbered snapshot to still report version={numbered_version!r}, got {numbered_after['version']!r}"
    )
    assert numbered_after["variants"][0]["templateConfiguration"]["text"]["text"] == variant[
        "templateConfiguration"
    ]["text"]["text"], "expected the immutable numbered version to be unaffected by UpdatePrompt"

    # Positive control: fetching DRAFT directly shows the same mutation.
    draft_after = bedrock.get_prompt(promptIdentifier=prompt_id)
    assert draft_after["version"] == "DRAFT", (
        f"expected the positive-control read to still address DRAFT, got {draft_after['version']!r}"
    )
    assert draft_after["variants"][0]["templateConfiguration"]["text"]["text"] == updated_variant[
        "templateConfiguration"
    ]["text"]["text"], "expected DRAFT's independent read to show the UpdatePrompt mutation"

    # DeletePrompt without a promptVersion removes the whole prompt: DRAFT and all
    # numbered versions must become unreachable.
    bedrock.delete_prompt(promptIdentifier=prompt_id)
    code_draft, message_draft = _error_eventually(lambda: bedrock.get_prompt(promptIdentifier=prompt_id))
    assert code_draft == "ResourceNotFoundException", (
        f"expected GetPrompt on the deleted DRAFT id to be ResourceNotFoundException, got {code_draft!r}"
    )
    assert message_draft == _missing_prompt_message("GetPrompt"), message_draft
    code_numbered, message_numbered = _error_eventually(lambda: bedrock.get_prompt(promptIdentifier=numbered_arn))
    assert code_numbered == "ResourceNotFoundException", (
        f"expected GetPrompt on the deleted numbered snapshot to be ResourceNotFoundException, got {code_numbered!r}"
    )

    # A mutation on the deleted id must also fail, not just a read.
    assert message_numbered == _missing_prompt_message("GetPrompt"), message_numbered
    mutation_code, mutation_message = _error(
        lambda: bedrock.update_prompt(
            promptIdentifier=prompt_id,
            name=created["name"],
            variants=[variant],
            defaultVariant="v1",
        )
    )
    assert mutation_code == "ResourceNotFoundException", (
        f"expected UpdatePrompt on the deleted prompt id to be ResourceNotFoundException, got {mutation_code!r}"
    )
    assert mutation_message == _missing_prompt_message("UpdatePrompt"), mutation_message


def _missing_prompt_message(operation):
    return (
        f"Couldn't perform {operation} operation. Failed to retrieve resource type Prompt because "
        "it doesn't exist. Check the resource ID and retry your request."
    )


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; an unexpected success
    raises, so a target that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _error_eventually(fn, timeout_s=30.0, interval_s=3.0):
    """Like _error, but tolerates successes while a just-issued delete propagates; still
    succeeding after timeout_s raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _error(fn)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _best_effort_delete_prompt(bedrock, prompt_id):
    try:
        bedrock.delete_prompt(promptIdentifier=prompt_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
