"""challenge-arn-wrong-resource-type-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "challenge-arn-wrong-resource-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["pca-connector-scep"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetChallengeMetadata rejects a ConnectorArn passed as ChallengeArn with ValidationException and
    its exact message, while a well-formed nonexistent ChallengeArn gets ResourceNotFoundException with
    its exact message."""
    scep = ctx.client("pca-connector-scep")
    account = ctx.client("sts").get_caller_identity()["Account"]
    connector_shaped_arn = (
        f"arn:aws:pca-connector-scep:{ctx.region}:{account}:connector/{uuid.uuid4()}"
    )

    error = _client_error(lambda: scep.get_challenge_metadata(ChallengeArn=connector_shaped_arn))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException, got {error.get('Code')!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{connector_shaped_arn}' at 'challengeArn' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: {_CHALLENGE_ARN_PATTERN}"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: a syntactically valid (but nonexistent) Challenge ARN is accepted by
    # validation and correctly reported as not found, proving the rejection above is about the
    # ARN shape and not a blanket failure of GetChallengeMetadata.
    challenge_shaped_arn = (
        f"arn:aws:pca-connector-scep:{ctx.region}:{account}:connector/{uuid.uuid4()}"
        f"/challenge/{uuid.uuid4()}"
    )
    control = _client_error(lambda: scep.get_challenge_metadata(ChallengeArn=challenge_shaped_arn))
    assert control.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {control.get('Code')!r}"
    )
    expected_control_message = f"Challenge was not found: {challenge_shaped_arn}."
    assert control.get("Message") == expected_control_message, (
        f"expected message {expected_control_message!r}, got {control.get('Message')!r}"
    )


from botocore.exceptions import ClientError  # noqa: E402


_CHALLENGE_ARN_PATTERN = (
    r"arn:aws(-[a-z]+)*:pca-connector-scep:[a-z]+(-[a-z]+)+-[1-9]\d*:\d{12}:connector\/"
    r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\/challenge\/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"
)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
