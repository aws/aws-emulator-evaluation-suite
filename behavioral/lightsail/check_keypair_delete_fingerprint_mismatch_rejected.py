"""keypair-delete-fingerprint-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "keypair-delete-fingerprint-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["lightsail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteKeyPair on a never-created name raises NotFoundException; with a mismatched expectedFingerprint
    it still deletes a non-default key pair, after which GetKeyPair and a second delete raise NotFoundException
    with the exact message."""
    ls = ctx.client("lightsail")
    name = ctx.unique_name("sim2real-ls-kp-")
    ghost_name = ctx.unique_name("sim2real-ls-kp-ghost-")

    # Boundary: deleting a key pair name that was never created is rejected outright.
    code, message = _error(lambda: ls.delete_key_pair(keyPairName=ghost_name))
    assert code == "NotFoundException", f"unexpected code deleting nonexistent key pair: {code!r}"
    assert message == f"The KeyPair does not exist: {ghost_name}", f"unexpected message: {message!r}"

    ls.create_key_pair(keyPairName=name, tags=[{"key": "sim2real", "value": CHECK}])
    deleted = False

    def _cleanup():
        if not deleted:
            ls.delete_key_pair(keyPairName=name)

    ctx.on_cleanup(_cleanup)

    real_fingerprint = ls.get_key_pair(keyPairName=name)["keyPair"]["fingerprint"]
    bogus_fingerprint = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
    assert bogus_fingerprint != real_fingerprint, (
        f"test setup invalid: bogus fingerprint collided with the real one {real_fingerprint!r}"
    )

    # Documented quirk, pinned down empirically: a mismatched expectedFingerprint is NOT
    # enforced for a non-default key pair -- the delete succeeds anyway.
    ls.delete_key_pair(keyPairName=name, expectedFingerprint=bogus_fingerprint)
    deleted = True
    code, message = _error(lambda: ls.get_key_pair(keyPairName=name))
    assert code == "NotFoundException", f"expected NotFoundException reading deleted key pair, got {code!r}"
    assert message == f"The KeyPair does not exist: {name}", f"unexpected message: {message!r}"

    # The dead id stays dead: a mutation against it fails the same way an independent read does.
    code, message = _error(lambda: ls.delete_key_pair(keyPairName=name))
    assert code == "NotFoundException", f"expected NotFoundException re-deleting already-deleted key pair, got {code!r}"
    assert message == f"The KeyPair does not exist: {name}", f"unexpected message: {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target accepting
    what real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
