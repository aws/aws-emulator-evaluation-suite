"""ai-prompt-version-concurrent-creation-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ai-prompt-version-concurrent-creation-race"
GROUP = "concurrency"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateAIPromptVersion racers never receive duplicate version numbers."""
    qc = ctx.client("qconnect")
    assistant_id = _create_active_assistant(ctx, qc)

    name = ctx.unique_name("sim2real-qc-prompt-")
    prompt_id = qc.create_ai_prompt(
        assistantId=assistant_id,
        name=name,
        type="QUERY_REFORMULATION",
        templateConfiguration={
            "textFullAIPromptEditTemplateConfiguration": {
                "text": (
                    "system: You are a helpful assistant that reformulates search queries.\n"
                    "messages:\n"
                    "- role: user\n"
                    "  content: |\n"
                    "    Reformulate this customer conversation for search: {{$.transcript}}\n"
                )
            }
        },
        visibilityStatus="SAVED",
        templateType="TEXT",
        modelId="us.amazon.nova-lite-v1:0",
        apiFormat="MESSAGES",
        tags={"sim2real": CHECK},
    )["aiPrompt"]["aiPromptId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_ai_prompt(assistantId=assistant_id, aiPromptId=prompt_id))
    )

    # AI Prompts (like AI Agents) require a PUBLISHED visibility status before a version can be
    # created from them.
    qc.update_ai_prompt(assistantId=assistant_id, aiPromptId=prompt_id, visibilityStatus="PUBLISHED")

    def _try_create_version():
        try:
            return qc.create_ai_prompt_version(assistantId=assistant_id, aiPromptId=prompt_id)
        except ClientError:
            return None

    first_version = _poll_until(
        _try_create_version,
        lambda v: v is not None,
        timeout_s=30.0,
        description="CreateAIPromptVersion to succeed after publishing the AI Prompt",
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_ai_prompt_version(
                assistantId=assistant_id, aiPromptId=prompt_id, versionNumber=first_version["versionNumber"]
            )
        )
    )

    racer_count = 5

    def _race(_i):
        try:
            resp = qc.create_ai_prompt_version(assistantId=assistant_id, aiPromptId=prompt_id)
            return ("ok", resp["versionNumber"])
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_race, range(racer_count)))

    successes = [v for kind, v in results if kind == "ok"]
    failures = [v for kind, v in results if kind == "error"]

    for version in successes:
        ctx.on_cleanup(
            lambda v=version: _ignore_not_found(
                lambda: qc.delete_ai_prompt_version(assistantId=assistant_id, aiPromptId=prompt_id, versionNumber=v)
            )
        )

    assert len(successes) >= 1, f"expected at least one racer to succeed, failures={failures}"
    assert len(successes) == len(set(successes)), f"duplicate version numbers assigned: {successes}"
    # A losing racer is refused on the SAVED alias the winners move.
    for code, message in failures:
        assert code == "ValidationException", f"unexpected failure code {code!r} (all: {failures})"
        assert message == "Failed to update SAVED alias.", message

    listed = qc.list_ai_prompt_versions(assistantId=assistant_id, aiPromptId=prompt_id)["aiPromptVersionSummaries"]
    listed_versions = {s["versionNumber"] for s in listed}
    assert set(successes) | {first_version["versionNumber"]} <= listed_versions, (
        f"ListAIPromptVersions {listed_versions} missing some created versions {set(successes)}"
    )


def _create_active_assistant(ctx, qc) -> str:
    name = ctx.unique_name("sim2real-qc-asst-")
    assistant_id = qc.create_assistant(name=name, type="AGENT", tags={"sim2real": CHECK})["assistant"][
        "assistantId"
    ]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_assistant(assistantId=assistant_id)))
    status = _poll_until(
        lambda: qc.get_assistant(assistantId=assistant_id)["assistant"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
        description="assistant to leave CREATING",
    )
    assert status == "ACTIVE", f"assistant {assistant_id} failed to activate: status={status}"
    return assistant_id


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"timed out after {timeout_s}s waiting for {description}, last value={value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
