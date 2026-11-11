"""server-side-default-encryption-enforced-without-policy."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-default-encryption-enforced-without-policy"
GROUP = "server-side"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCollection without a matching encryption policy fails with ValidationException and its exact
    message; with an AWSOwnedKey policy the collection reaches ACTIVE with a kmsKeyArn, and the stored
    policy has AWSOwnedKey true and no KmsARN.
    """
    osc = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-defenc-")
    policy_name = _short_name(ctx, "sim2real-defenc-")

    # Positive control: confirm, rather than merely narrate, the premise this check's
    # subject depends on -- with no matching encryption security policy at all, the
    # service rejects CreateCollection outright.
    error_code, error_message = _error(
        lambda: osc.create_collection(name=name, type="SEARCH", standbyReplicas="DISABLED")
    )
    assert error_code == "ValidationException", (
        f"expected ValidationException rejecting CreateCollection with no matching "
        f"encryption security policy, got {error_code!r}"
    )
    expected_message = (
        f"No matching security policy of encryption type found for collection name: {name}. "
        "Please create security policy of encryption type for this collection."
    )
    assert error_message == expected_message, f"expected message {expected_message!r}, got {error_message!r}"

    enc_doc = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}],
        "AWSOwnedKey": True,
    }
    osc.create_security_policy(type="encryption", name=policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _safe(lambda: osc.delete_security_policy(type="encryption", name=policy_name)))

    # No encryptionConfig / KMS key ever specified anywhere by the client.
    created = osc.create_collection(
        name=name,
        type="SEARCH",
        standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": "default-encryption"}],
    )
    collection_id = created["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_collection(osc, collection_id))

    _wait_collection_active(osc, collection_id, timeout_s=600)

    detail = osc.batch_get_collection(ids=[collection_id])["collectionDetails"][0]
    assert detail["status"] == "ACTIVE", f"expected collection {collection_id} to reach ACTIVE, got {detail['status']!r}"
    kms_key_arn = detail.get("kmsKeyArn")
    assert isinstance(kms_key_arn, str) and len(kms_key_arn) > 0, (
        f"expected a populated kmsKeyArn from default (AWS-owned key) encryption, got {kms_key_arn!r}"
    )

    policy_detail = osc.get_security_policy(type="encryption", name=policy_name)["securityPolicyDetail"]
    stored_policy = policy_detail["policy"]
    assert stored_policy.get("AWSOwnedKey") is True, (
        f"expected the stored encryption policy to declare AWSOwnedKey=True, got {stored_policy!r}"
    )
    assert "KmsARN" not in stored_policy, (
        f"expected no customer-managed KmsARN in an AWS-owned-key policy, got {stored_policy!r}"
    )


def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _safe(fn: Callable[[], Any]) -> None:
    """Best-effort teardown call: any error (typically not-found) is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the error ``fn`` raises. An unexpected success raises AssertionError, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _best_effort_delete_collection(osc, collection_id):
    _safe(lambda: osc.delete_collection(id=collection_id))


def _wait_collection_active(osc, collection_id, timeout_s=600, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[collection_id]).get("collectionDetails", [])
        if details:
            status = details[0]["status"]
            if status == "ACTIVE":
                return
            if status == "FAILED":
                raise AssertionError(f"collection {collection_id} entered FAILED state while creating")
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
