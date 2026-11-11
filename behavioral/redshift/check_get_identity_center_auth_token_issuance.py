"""get-identity-center-auth-token-issuance."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-identity-center-auth-token-issuance"
GROUP = "data-plane"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIdentityCenterAuthToken from a caller with plain IAM credentials is rejected with
    UnsupportedOperation "Request rejected: Not an IDC user acting", while the same credentials
    still describe clusters."""
    redshift = ctx.client("redshift")

    # Positive control: plain IAM credentials work fine for an ordinary Redshift
    # control-plane call, isolating that the rejection below is specific to lacking an IdC
    # identity, not a general credentials/connectivity failure.
    redshift.describe_clusters(MaxRecords=20)

    placeholder_cluster_id = ctx.unique_name("sim2real-idc-placeholder-")
    error = _get_error(
        lambda: redshift.get_identity_center_auth_token(ClusterIds=[placeholder_cluster_id])
    )
    assert error.get("Code") == "UnsupportedOperation", f"unexpected code: {error!r}"
    # The message is the discriminator that separates "not an IdC caller" (this check's
    # contract) from an unrelated malformed-request or no-permissions UnsupportedOperation.
    message = error.get("Message")
    expected = "Request rejected: Not an IDC user acting"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # Effect absent by construction: the call raised, so no Token/ExpirationTime was minted.


def _get_error(fn) -> dict:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
