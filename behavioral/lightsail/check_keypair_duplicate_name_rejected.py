"""keypair-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "keypair-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["lightsail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateKeyPair with a name that already exists is rejected, leaving the original key pair
    untouched; once the conflicting key pair is gone, the identical call succeeds."""
    ls = ctx.client("lightsail")
    name = ctx.unique_name("sim2real-ls-kp-")
    other_name = ctx.unique_name("sim2real-ls-kp-other-")
    tag_spec = [{"key": "sim2real", "value": CHECK}]

    first = ls.create_key_pair(keyPairName=name, tags=tag_spec)["keyPair"]
    ctx.on_cleanup(lambda: _delete_if_present(ls, name))
    assert first["name"] == name, f"expected created key pair name {name!r}, got {first['name']!r}"
    # CreateKeyPair's inline keyPair does not reliably include "fingerprint" (it's an optional
    # field per the KeyPair shape); fetch it via GetKeyPair for a stable baseline.
    original_fingerprint = ls.get_key_pair(keyPairName=name)["keyPair"]["fingerprint"]

    code, message = _error(lambda: ls.create_key_pair(keyPairName=name))
    assert code == "InvalidInputException", f"unexpected code for duplicate key pair name: {code!r}"
    assert message == f"Some names are already in use: {name}", f"unexpected message: {message!r}"

    unchanged = ls.get_key_pair(keyPairName=name)["keyPair"]
    assert unchanged["fingerprint"] == original_fingerprint, "key pair fingerprint changed after rejected duplicate create"

    # Restore: once the conflicting key pair is deleted, the identical CreateKeyPair call
    # succeeds — proving the rejection was specifically about the name conflict, not a permanent
    # block on the name.
    ls.delete_key_pair(keyPairName=name)
    gone_code, gone_message = _error(lambda: ls.get_key_pair(keyPairName=name))
    assert gone_code == "NotFoundException", f"unexpected code reading deleted key pair: {gone_code!r}"
    assert gone_message == f"The KeyPair does not exist: {name}", f"unexpected message: {gone_message!r}"

    restored = ls.create_key_pair(keyPairName=name, tags=tag_spec)["keyPair"]
    assert restored["name"] == name, f"expected restored key pair name {name!r}, got {restored['name']!r}"
    restored_fingerprint = ls.get_key_pair(keyPairName=name)["keyPair"]["fingerprint"]
    assert restored_fingerprint, "restored key pair reports no fingerprint"

    # Positive control: a genuinely new name still succeeds.
    ls.create_key_pair(keyPairName=other_name, tags=tag_spec)
    ctx.on_cleanup(lambda: _delete_if_present(ls, other_name))
    control = ls.get_key_pair(keyPairName=other_name)["keyPair"]
    assert control["name"] == other_name, f"expected control key pair name {other_name!r}, got {control['name']!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _delete_if_present(ls, key_pair_name):
    from botocore.exceptions import ClientError

    try:
        ls.delete_key_pair(keyPairName=key_pair_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
