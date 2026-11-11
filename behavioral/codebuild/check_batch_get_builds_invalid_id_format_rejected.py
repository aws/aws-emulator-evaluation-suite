"""batch-get-builds-invalid-id-format-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "batch-get-builds-invalid-id-format-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetBuilds refuses an id that is not "<project-name>:<uuid>" with InvalidInputException, while
    a well-formed id of a missing build is returned in buildsNotFound."""
    codebuild = ctx.client("codebuild")
    malformed_id = "this-id-has-no-colon-separator"

    def _get_malformed() -> None:
        codebuild.batch_get_builds(ids=[malformed_id])

    code, message = _error(_get_malformed)
    assert (code, message) == (
        "InvalidInputException",
        "Invalid build ID provided",
    ), (code, message)

    # Positive control: a well-formed id for a build that doesn't exist is reported
    # as not-found, not as an error -- confirming the negative above is about format,
    # not existence.
    well_formed_missing_id = f"{ctx.unique_name('sim2real-cb-nope-')}:{uuid.uuid4()}"
    resp = codebuild.batch_get_builds(ids=[well_formed_missing_id])
    assert resp["builds"] == [], f"expected no builds for a missing id, got {resp['builds']!r}"
    assert resp["buildsNotFound"] == [well_formed_missing_id], (
        f"expected buildsNotFound == [{well_formed_missing_id!r}], got {resp['buildsNotFound']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so an over-permissive target is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
