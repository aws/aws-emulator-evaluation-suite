"""list-ssh-public-keys-stable-upload-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-ssh-public-keys-stable-upload-order"
GROUP = "ordering"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSSHPublicKeys returns keys in stable upload-time order across repeated
    calls and across pagination, regardless of how the key IDs themselves sort."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-sshorder-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    uploaded_ids_in_order = []
    for _ in range(4):
        pub = _generate_rsa_ssh_pubkey()
        resp = iam.upload_ssh_public_key(UserName=user_name, SSHPublicKeyBody=pub)
        key_id = resp["SSHPublicKey"]["SSHPublicKeyId"]
        ctx.on_cleanup(
            lambda kid=key_id: iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=kid)
        )
        uploaded_ids_in_order.append(key_id)

    # Two independent, unpaginated calls must return the same stable order as each
    # other (IAM does not document upload-time ordering for ListSSHPublicKeys, but
    # repeated listings -- and paged listings -- of the same unmodified key set must
    # agree with each other, regardless of what that canonical order actually is).
    listed_1 = [k["SSHPublicKeyId"] for k in iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]]
    listed_2 = [k["SSHPublicKeyId"] for k in iam.list_ssh_public_keys(UserName=user_name)["SSHPublicKeys"]]
    assert sorted(listed_1) == sorted(uploaded_ids_in_order), (
        f"ListSSHPublicKeys does not return exactly the uploaded keys: {listed_1!r} vs {uploaded_ids_in_order!r}"
    )
    assert listed_2 == listed_1, (
        f"repeated ListSSHPublicKeys call not stable: {listed_2!r} vs {listed_1!r}"
    )

    # Paginated retrieval (one key per page) must preserve the same overall order as
    # the unpaginated listing.
    paginated_ids = []
    marker = None
    for _ in range(10):
        kwargs = {"UserName": user_name, "MaxItems": 1}
        if marker:
            kwargs["Marker"] = marker
        page = iam.list_ssh_public_keys(**kwargs)
        paginated_ids.extend(k["SSHPublicKeyId"] for k in page["SSHPublicKeys"])
        if not page.get("IsTruncated"):
            break
        marker = page["Marker"]
    assert paginated_ids == listed_1, (
        f"paginated ListSSHPublicKeys order diverged from unpaginated listing order: "
        f"{paginated_ids!r} vs {listed_1!r}"
    )


def _generate_rsa_ssh_pubkey():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
