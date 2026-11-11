"""start-speaker-search-task-pipeline-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-speaker-search-task-pipeline-not-found"
GROUP = "errors"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSpeakerSearchTask and GetSpeakerSearchTask on a nonexistent pipeline both fail with
    ForbiddenException "AWS account is not enabled" (voice analytics needs per-account
    enablement); a preceding ListMediaPipelines succeeds, so it is no credentials failure."""
    chime = ctx.client("chime-sdk-media-pipelines")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # positive control: the account and credentials are otherwise healthy for this
    # service — a plain, unrelated read succeeds.
    chime.list_media_pipelines()

    bogus_identifier = "00000000-0000-0000-0000-000000000000"
    bogus_task_id = "11111111-1111-1111-1111-111111111111"
    bogus_domain_arn = (
        f"arn:aws:chime:{ctx.region}:{account_id}:voice-profile-domain/"
        "00000000-0000-0000-0000-000000000000"
    )
    error = _client_error(
        lambda: chime.start_speaker_search_task(
            Identifier=bogus_identifier, VoiceProfileDomainArn=bogus_domain_arn
        )
    )
    assert error["Code"] == "ForbiddenException", f"actual error: {error!r}"
    assert error["Message"] == "AWS account is not enabled", (
        f"unexpected ForbiddenException message: {error['Message']!r}"
    )

    # GetSpeakerSearchTask on the same pipeline is refused the same way.
    get_error = _client_error(
        lambda: chime.get_speaker_search_task(
            Identifier=bogus_identifier, SpeakerSearchTaskId=bogus_task_id
        )
    )
    assert get_error["Code"] == "ForbiddenException", f"actual error: {get_error!r}"
    assert get_error["Message"] == "AWS account is not enabled", (
        f"unexpected ForbiddenException message: {get_error['Message']!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a target
    that accepts what AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
