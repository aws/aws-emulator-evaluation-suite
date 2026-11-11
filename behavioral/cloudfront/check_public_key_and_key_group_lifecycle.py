"""public-key-and-key-group-lifecycle."""
from __future__ import annotations

import itertools
from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()

def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource; a resource the check
    itself already deleted is left alone."""
    try:
        resp = get_fn(Id=resource_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "").startswith("NoSuch"):
            return
        raise
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"

def _generate_rsa_public_key_pem():
    """Generate a fresh, structurally-valid RSA public key PEM for CreatePublicKey tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("ascii")

CHECK = "public-key-and-key-group-lifecycle"
GROUP = 'security'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublicKey and KeyGroup CRUD: create a key, group it, confirm membership, tear both down."""
    cf = ctx.client("cloudfront")
    key_name = ctx.unique_name("sim2real-behav-pk-")
    created_key = cf.create_public_key(PublicKeyConfig={
        "CallerReference": _caller_reference(ctx, "pk"),
        "Name": key_name,
        "EncodedKey": _generate_rsa_public_key_pem(),
    })
    key_id = created_key["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_public_key, cf.delete_public_key, key_id))

    group_name = ctx.unique_name("sim2real-behav-kg-")
    created_group = cf.create_key_group(KeyGroupConfig={
        "Name": group_name,
        "Items": [key_id],
    })
    group_id = created_group["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_key_group, cf.delete_key_group, group_id))
    assert created_group["KeyGroup"]["KeyGroupConfig"]["Items"] == [key_id]

    got_group = cf.get_key_group(Id=group_id)
    got_items = got_group["KeyGroup"]["KeyGroupConfig"]["Items"]
    assert got_items == [key_id], f"expected independent read to confirm membership [{key_id}], got {got_items}"
    cf.delete_key_group(Id=group_id, IfMatch=got_group["ETag"])

    group_gone_code, group_gone_message = _error(lambda: cf.get_key_group(Id=group_id))
    assert group_gone_code == "NoSuchResource", f"expected NoSuchResource after delete, got {group_gone_code}"
    expected_group = "The specified key group does not exist."
    assert group_gone_message == expected_group, (
        f"expected message {expected_group!r}, got {group_gone_message!r}"
    )

    got_key = cf.get_public_key(Id=key_id)
    cf.delete_public_key(Id=key_id, IfMatch=got_key["ETag"])

    code, message = _error(lambda: cf.get_public_key(Id=key_id))
    assert code == "NoSuchPublicKey", f"expected NoSuchPublicKey after delete, got {code}"
    expected = "The specified CloudFront public key does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
