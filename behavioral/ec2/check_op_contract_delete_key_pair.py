"""op-contract-delete-key-pair."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-key-pair"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteKeyPair: DryRun boundary, real delete removes the pair, and delete is idempotent."""
    ec2 = ctx.client("ec2")
    key_name = ctx.unique_name("sim2real-kp-")

    created = ec2.create_key_pair(
        KeyName=key_name,
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=key_name))

    described = ec2.describe_key_pairs(KeyNames=[key_name])["KeyPairs"]
    assert len(described) == 1 and described[0]["KeyPairId"] == created["KeyPairId"], (
        f"expected exactly 1 described key pair with id {created['KeyPairId']!r}, got {described}"
    )

    # error boundary: DryRun short-circuits with DryRunOperation, key pair survives
    code, message = _error(lambda: ec2.delete_key_pair(KeyName=key_name, DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    survivors = ec2.describe_key_pairs(KeyNames=[key_name])["KeyPairs"]
    assert len(survivors) == 1, f"expected key pair to survive DryRun delete, got {survivors}"

    # success path: real delete removes it
    resp = ec2.delete_key_pair(KeyName=key_name)
    assert resp["Return"] is True, f"expected Return=True on real delete, got {resp.get('Return')!r}"

    code, message = _error(lambda: ec2.describe_key_pairs(KeyNames=[key_name]))
    assert code == "InvalidKeyPair.NotFound", f"expected InvalidKeyPair.NotFound, got {code}"
    assert message == f"The key pair '{key_name}' does not exist", f"unexpected message {message!r}"

    # distinct fidelity signal, measured against real AWS (not guessed): DeleteKeyPair
    # by name is idempotent - a second delete of an already-gone key pair does NOT raise
    # and still reports Return=True, indistinguishable from a real delete.
    resp2 = ec2.delete_key_pair(KeyName=key_name)
    assert resp2.get("Return") is True, f"expected Return=True on no-op re-delete, got {resp2.get('Return')!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
