"""get-speaker-search-task-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-speaker-search-task-not-found"
GROUP = "errors"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSpeakerSearchTask with a nonexistent Identifier and task id fails with ForbiddenException
    "AWS account is not enabled": voice analytics needs per-account enablement. A preceding
    ListMediaPipelines call succeeds, so the refusal is not a credentials failure."""
    chime = ctx.client("chime-sdk-media-pipelines")

    chime.list_media_pipelines()

    bogus_identifier = "00000000-0000-0000-0000-000000000000"
    bogus_task_id = "11111111-1111-1111-1111-111111111111"
    error = _client_error(
        lambda: chime.get_speaker_search_task(
            Identifier=bogus_identifier, SpeakerSearchTaskId=bogus_task_id
        )
    )
    code = error.get("Code")
    message = error.get("Message")
    assert code == "ForbiddenException", f"expected ForbiddenException, got {code}"
    assert message == "AWS account is not enabled", (
        f"unexpected ForbiddenException message: {message!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a target
    that accepts what AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
