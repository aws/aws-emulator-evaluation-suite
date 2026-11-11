"""validate-cloud-connector-nonexistent-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-cloud-connector-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateCloudConnector on an unknown CloudConnectorId is rejected with
    ResourceNotFoundException rather than returning an empty/success validation
    result for a connector that does not exist.
    """
    ssm = ctx.client("ssm")

    # Positive control: the CloudConnector subsystem itself is reachable and not
    # blanket-denying every call. Without this, "rejects an unknown id" is
    # indistinguishable from "rejects every ValidateCloudConnector call".
    listing = ssm.list_cloud_connectors()
    assert "CloudConnectors" in listing, f"unexpected ListCloudConnectors response: {listing}"

    unknown_id = str(uuid.uuid4())
    assert unknown_id not in {c["CloudConnectorId"] for c in listing["CloudConnectors"]}, (
        f"the chosen unknown id {unknown_id} collided with a real connector"
    )
    code, message = _error(lambda: ssm.validate_cloud_connector(CloudConnectorId=unknown_id))
    assert code == "ResourceNotFoundException", f"unexpected code: {code}"
    assert message == 'CloudConnector not found for account.', f"unexpected message: {message!r}"

    # Effect absent: an independent read at the destination, through a different
    # operation than the one under test, confirms no connector materialized as a
    # side effect of the failed validation.
    get_code, get_message = _error(lambda: ssm.get_cloud_connector(CloudConnectorId=unknown_id))
    assert get_code == "ResourceNotFoundException", f"unexpected code: {get_code}"
    assert get_message == 'CloudConnector not found for account.', f"unexpected message: {get_message!r}"

    # a second, distinct unknown id gets the identical rejection (deterministic,
    # not a one-off 404 on a coincidentally-colliding id)
    other_unknown_id = str(uuid.uuid4())
    assert other_unknown_id != unknown_id, "uuid4 collided across two calls"
    code2, message2 = _error(
        lambda: ssm.validate_cloud_connector(CloudConnectorId=other_unknown_id)
    )
    assert code2 == "ResourceNotFoundException", f"unexpected code: {code2}"
    assert message2 == 'CloudConnector not found for account.', f"unexpected message: {message2!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


