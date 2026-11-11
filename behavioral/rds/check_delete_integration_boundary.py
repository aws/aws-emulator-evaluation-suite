"""delete-integration-boundary."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-integration-boundary"
GROUP = 'integrations'
SERVICES = ['rds']

ERR_INTEGRATION_NOT_FOUND = "IntegrationNotFoundFault"


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a delete on an identifier that was never created is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"DeleteIntegration on a never-created identifier SUCCEEDED and returned {result!r}, "
        f"expected it to raise {ERR_INTEGRATION_NOT_FOUND}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIntegration with an unknown IntegrationIdentifier is rejected with
    IntegrationNotFoundFault."""
    rds = ctx.client("rds")
    bogus_id = str(uuid.uuid4())
    code, message = _error_code(
        lambda: rds.delete_integration(IntegrationIdentifier=bogus_id)
    )
    assert code == ERR_INTEGRATION_NOT_FOUND, (
        f"expected {ERR_INTEGRATION_NOT_FOUND}, got {code}"
    )
    # The integration ARN carries the caller's account id, which this check never reads.
    assert message.startswith(f"Integration with identifier arn:aws:rds:{ctx.region}:"), message
    assert message.endswith(
        f":integration:{bogus_id} could not be found. The integration might have been deleted, or you "
        "provided an incorrect identifier. Check the integration identifier and try again."
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
