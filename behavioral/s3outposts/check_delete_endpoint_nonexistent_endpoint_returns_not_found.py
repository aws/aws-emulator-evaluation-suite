"""delete-endpoint-nonexistent-endpoint-returns-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-endpoint-nonexistent-endpoint-returns-not-found"
GROUP = "error-semantics"
SERVICES = ["s3outposts"]

OUTPOST_NOT_FOUND = "The specified outpost does not exist, or does not have S3 capacity provisioned on it."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEndpoint for an EndpointId/OutpostId combination that does not exist fails with
    ResourceNotFoundException."""
    s3o = ctx.client("s3outposts")
    # A well-formed but unowned 12-digit account-style OutpostId (the shared-outpost branch of
    # the OutpostId pattern) paired with a well-formed but never-issued EndpointId.
    outpost_id = "111122223333"
    endpoint_id = "B1C2D3E4F5G6H7I8J9K"

    code, message = _error(
        lambda: s3o.delete_endpoint(EndpointId=endpoint_id, OutpostId=outpost_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code!r}"
    )
    assert message == OUTPOST_NOT_FOUND, f"message={message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
