"""list-tags-for-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-not-found"
GROUP = "errors"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a missing playback key pair ARN fails NotFoundException "Resource was not found",
    also after a real key pair is deleted, while GetPlaybackKeyPair fails ResourceNotFoundException."""
    ivs = ctx.client("ivs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:ivs:{ctx.region}:{account}:playback-key/00000000-0000-0000-0000-000000000000"

    error = _error(lambda: ivs.list_tags_for_resource(resourceArn=bogus_arn))
    assert error["Code"] == "NotFoundException", (
        f"ListTagsForResource on a fabricated playback-key-pair ARN: "
        f"expected NotFoundException, got {error['Code']}"
    )
    assert error["Message"] == "Resource was not found", repr(error["Message"])

    # Positive control: a real playback key pair's tags round-trip correctly.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP384R1())
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    created = ivs.import_playback_key_pair(
        publicKeyMaterial=pem,
        name=ctx.unique_name("sim2real-ivs-tagcheck-"),
        tags={"probe": "sim2real"},
    )["keyPair"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete(ivs.delete_playback_key_pair, arn=arn))

    real_tags = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert real_tags == {"probe": "sim2real"}, (
        f"ListTagsForResource on a real, live playback key pair: "
        f"expected {{'probe': 'sim2real'}}, got {real_tags}"
    )

    # Delete it for real, then re-run both reads against a resource that
    # indisputably existed and is now genuinely gone: GetPlaybackKeyPair takes
    # the ordinary IVS not-found path, while ListTagsForResource -- tested above
    # only against a fabricated ARN -- must raise the SAME NotFoundException here.
    ivs.delete_playback_key_pair(arn=arn)

    get_error = _error(lambda: ivs.get_playback_key_pair(arn=arn))
    assert get_error["Code"] == "ResourceNotFoundException", (
        f"GetPlaybackKeyPair on a deleted key pair: "
        f"expected ResourceNotFoundException, got {get_error['Code']}"
    )
    assert get_error["Message"] == f"Resource: {arn} not found", repr(get_error["Message"])

    list_tags_error = _error(lambda: ivs.list_tags_for_resource(resourceArn=arn))
    assert list_tags_error["Code"] == "NotFoundException", (
        f"ListTagsForResource on a deleted key pair: "
        f"expected NotFoundException, got {list_tags_error['Code']}"
    )
    assert list_tags_error["Message"] == "Resource was not found", repr(list_tags_error["Message"])


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _safe_delete(fn, **kwargs) -> None:
    from botocore.exceptions import ClientError
    try:
        fn(**kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "NotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


