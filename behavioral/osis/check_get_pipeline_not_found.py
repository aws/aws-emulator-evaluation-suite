"""get-pipeline-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-pipeline-not-found"
GROUP = "error-semantics"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPipeline on a syntactically-valid but never-created PipelineName raises
    ResourceNotFoundException, not a generic/validation error."""
    osis = ctx.client("osis")
    missing_name = ctx.unique_name("sim2real-behav-")

    error = _client_error(lambda: osis.get_pipeline(PipelineName=missing_name))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error.get('Code')!r}"
    )
    expected = "The pipeline could not be found"
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return the botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected ResourceNotFoundException, but GetPipeline SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
