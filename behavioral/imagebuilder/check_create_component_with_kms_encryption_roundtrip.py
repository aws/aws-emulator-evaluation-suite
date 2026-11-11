"""create-component-with-kms-encryption-roundtrip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-component-with-kms-encryption-roundtrip"
GROUP = "component-data-plane"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComponent with a kmsKeyId marks the component encrypted with that key, per GetComponent."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-ib-kms-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    doc = (
        f"name: {name}\n"
        "description: kms-encrypted component\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )
    resp = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=doc,
        kmsKeyId=key_arn,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ib.delete_component(componentBuildVersionArn=arn)))

    got = ib.get_component(componentBuildVersionArn=arn)["component"]
    assert got["encrypted"] is True, f"expected encrypted=True for a component created with kmsKeyId, got {got.get('encrypted')!r}"
    assert got["kmsKeyId"] == key_arn, f"expected kmsKeyId {key_arn!r} on the component, got {got.get('kmsKeyId')!r}"

    # positive control: a component created without kmsKeyId is not marked encrypted
    plain_name = ctx.unique_name("sim2real-ib-comp-plain-")
    plain_resp = ib.create_component(
        name=plain_name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=doc.replace(name, plain_name),
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    plain_arn = plain_resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ib.delete_component(componentBuildVersionArn=plain_arn)))
    plain_got = ib.get_component(componentBuildVersionArn=plain_arn)["component"]
    assert plain_got.get("kmsKeyId") != key_arn, (
        f"expected the plain component's kmsKeyId to differ from the explicit test key, got {plain_got.get('kmsKeyId')!r}"
    )

    # deletes prove gone and unusable: the plain component is deleted in-check, not only in teardown
    ib.delete_component(componentBuildVersionArn=plain_arn)
    code, msg = _error(lambda: ib.get_component(componentBuildVersionArn=plain_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted component, got {code!r}"
    )
    expected = f"The following required resource 'Component' cannot be found: '{plain_arn}'."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"
    code, msg = _error(lambda: ib.delete_component(componentBuildVersionArn=plain_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted component, got {code!r}"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


# ===== helpers =====
def _safe(fn):
    """Run a teardown delete; only an already-deleted resource is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises, so an
    accepted call is reported as accepted rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
