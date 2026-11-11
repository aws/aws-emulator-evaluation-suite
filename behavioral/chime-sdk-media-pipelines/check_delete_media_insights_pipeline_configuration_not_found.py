"""delete-media-insights-pipeline-configuration-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-media-insights-pipeline-configuration-not-found"
GROUP = "errors"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMediaInsightsPipelineConfiguration on a nonexistent Identifier returns
    NotFoundException instead of succeeding silently."""
    chime = ctx.client("chime-sdk-media-pipelines")

    bogus_identifier = ctx.unique_name("sim2real-no-such-config-")
    error = _client_error(
        lambda: chime.delete_media_insights_pipeline_configuration(Identifier=bogus_identifier)
    )
    assert error["Code"] == "NotFoundException", f"expected NotFoundException, got {error!r}"
    assert error["Message"] == "Unable to find the requested identifier", (
        f"unexpected NotFoundException message: {error['Message']!r}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
