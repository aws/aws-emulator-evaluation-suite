"""get-key-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-key-not-found"
GROUP = "error-semantics"
SERVICES = ["payment-cryptography"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetKey on a syntactically valid but nonexistent KeyArn raises ResourceNotFoundException,
    while the same call against the real key it was derived from succeeds."""
    pc = ctx.client("payment-cryptography")
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    created = pc.create_key(KeyAttributes=key_attributes, Exportable=True)["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))

    # positive control: the real key is reachable
    fetched = pc.get_key(KeyIdentifier=arn)["Key"]["KeyArn"]
    assert fetched == arn, f"expected GetKey to return {arn!r}, got {fetched!r}"

    # flip the last character of the key id portion to produce a well-formed, nonexistent ARN
    bogus_arn = arn[:-1] + ("0" if arn[-1] != "0" else "1")
    response = _client_error(lambda: pc.get_key(KeyIdentifier=bogus_arn))
    error = response.get("Error", {})
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected GetKey({bogus_arn!r}) to raise ResourceNotFoundException, got {error!r}"
    )
    # AWS sends no message for a missing key; it names the key in ResourceId instead
    assert error.get("Message", "") == "", (
        f"expected GetKey({bogus_arn!r}) to carry an empty message, got {error.get('Message')!r}"
    )
    assert response.get("ResourceId") == bogus_arn, (
        f"expected ResourceId={bogus_arn!r}, got {response.get('ResourceId')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error response. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
