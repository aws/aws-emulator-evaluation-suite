"""list-jobs-max-results-range-validation-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-jobs-max-results-range-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehendmedical"]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEntitiesDetectionV2Jobs with MaxResults 501 and 0 (validation off in the client, so the service
    judges them) fails with InvalidRequestException and exact messages; MaxResults 10 returns the list."""
    cm = ctx.client("comprehendmedical")

    # Positive control (validated client): a value inside the documented range succeeds normally.
    resp = cm.list_entities_detection_v2_jobs(MaxResults=10)
    assert "ComprehendMedicalAsyncJobPropertiesList" in resp

    raw = ctx.client("comprehendmedical", config=Config(parameter_validation=False))

    # Break exactly one thing: MaxResults above the documented ceiling, on the wire.
    code_over, message_over = _error(lambda: raw.list_entities_detection_v2_jobs(MaxResults=501))
    assert code_over == "InvalidRequestException", f"expected InvalidRequestException, got {code_over}"
    expected_over = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 500"
    )
    assert message_over == expected_over, f"expected message {expected_over!r}, got {message_over!r}"

    # Break exactly one thing: MaxResults below the documented floor, on the wire.
    code_under, message_under = _error(lambda: raw.list_entities_detection_v2_jobs(MaxResults=0))
    assert code_under == "InvalidRequestException", f"expected InvalidRequestException, got {code_under}"
    expected_under = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1"
    )
    assert message_under == expected_under, f"expected message {expected_under!r}, got {message_under!r}"

    # Control still succeeds through the raw (unvalidated) client too.
    resp_raw = raw.list_entities_detection_v2_jobs(MaxResults=10)
    assert "ComprehendMedicalAsyncJobPropertiesList" in resp_raw


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
