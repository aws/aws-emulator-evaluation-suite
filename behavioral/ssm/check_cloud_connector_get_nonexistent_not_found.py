"""cloud-connector-get-nonexistent-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloud-connector-get-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_NOT_FOUND = "CloudConnector not found for account."


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCloudConnector on an unknown connector id returns ResourceNotFoundException, while
    the cloud-connector listing API on the same account/region still works normally and does
    not carry the fabricated id."""
    ssm = ctx.client("ssm")
    bogus_id = str(uuid.uuid4())

    # Positive control: the API surface itself is healthy -- listing connectors succeeds, and
    # since this id was never created it is absent from that listing, proving the failure
    # below is specific to the unknown id and not a broken client/endpoint.
    listing = ssm.list_cloud_connectors()
    listed_ids = {c["CloudConnectorId"] for c in listing["CloudConnectors"]}
    assert bogus_id not in listed_ids, f"fabricated id {bogus_id} unexpectedly present in {listed_ids}"

    code, message = _error_code(lambda: ssm.get_cloud_connector(CloudConnectorId=bogus_id))
    assert code == "ResourceNotFoundException", f"unexpected code: {code}"
    assert message == _NOT_FOUND, f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
