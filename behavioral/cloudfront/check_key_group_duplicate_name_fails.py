"""key-group-duplicate-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts the duplicate is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource."""
    resp = get_fn(Id=resource_id)
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

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

CHECK = "key-group-duplicate-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateKeyGroup with a Name already in use MUST fail with KeyGroupAlreadyExists."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()
    pk_name = ctx.unique_name("sim2real-behav-pk-")
    pk_resp = cf.create_public_key(
        PublicKeyConfig={"CallerReference": pk_name, "Name": pk_name, "EncodedKey": pem}
    )
    key_id = pk_resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_public_key, cf.delete_public_key, key_id))

    kg_name = ctx.unique_name("sim2real-behav-kg-")
    kg_cfg = {"Name": kg_name, "Items": [key_id], "Comment": "behavioral test"}
    create_resp = cf.create_key_group(KeyGroupConfig=kg_cfg)
    kg_id = create_resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_key_group, cf.delete_key_group, kg_id))

    code, message = _error(lambda: cf.create_key_group(KeyGroupConfig=kg_cfg))
    assert code == "KeyGroupAlreadyExists", f"expected KeyGroupAlreadyExists, got {code}"
    assert message == "Another key group with the same name already exists within the aws account.", (
        f"expected AWS's exact duplicate-name message, got {message!r}"
    )

    # effect absent, via an independent read at the destination: exactly one key group
    # with this Name exists, it is the original, and its Items are untouched by the
    # rejected duplicate create.
    listed = cf.list_key_groups(MaxItems="100")["KeyGroupList"].get("Items", [])
    matching = [item for item in listed if item["KeyGroup"]["KeyGroupConfig"]["Name"] == kg_name]
    assert len(matching) == 1, f"expected exactly 1 key group named {kg_name!r}, found {len(matching)}"
    assert matching[0]["KeyGroup"]["Id"] == kg_id, (
        f"expected the matching key group to be the original {kg_id!r}, got {matching[0]['KeyGroup']['Id']!r}"
    )
    unaffected = cf.get_key_group(Id=kg_id)["KeyGroup"]["KeyGroupConfig"]
    assert unaffected["Items"] == [key_id], (
        f"original key group's Items must be untouched by the rejected duplicate, got {unaffected['Items']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
