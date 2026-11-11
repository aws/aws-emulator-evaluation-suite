"""create-collection-without-encryption-config-or-policy-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-collection-without-encryption-config-or-policy-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]

# AWS behaviors this check relies on:
#   1. THE REFUSAL EXISTS. CreateCollection with neither `encryptionConfig` nor a matching
#      encryption policy is refused -- the NextGen architecture does NOT default the key the way it
#      silently ignores the Classic account-level OCU ceiling; encryption-at-rest enforcement and
#      that capacity ceiling are independent contracts.
#   2. THE ERROR CODE is ValidationException, as asserted.
#   3. THE MESSAGE DISCRIMINATOR: the refusal message names encryption (`_ENCRYPTION_TOKENS`).
#   4. THE TWO ROUTES ARE ALTERNATIVES: either an inline `encryptionConfig` or a matching
#      encryption policy alone satisfies the requirement.
#   5. The restored collection's `kmsKeyArn` is the literal sentinel string `"auto"` for an
#      AWSOwnedKey policy, not an ARN containing `:kms:`, so the check asserts only that the field
#      is populated.

# ===== helpers =====

STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"

_ACTIVE_BUDGET_S = 300.0
_DELETE_BUDGET_S = 180.0

# Tokens (see note 3 above) that make an encryption-policy refusal separable from any
# other ValidationException. Lowercased substring match; all listed tokens must be present.
_ENCRYPTION_TOKENS = ("encryption",)

#: Violates CollectionName's ``^[a-z][a-z0-9-]+$`` pattern (leading digit) while satisfying its
#: length trait, so botocore forwards it and the SERVICE issues the rejection.
_MALFORMED_NAME = "1-invalid-collection-name"


def _aoss_name(ctx, prefix: str, maxlen: int = 32) -> str:
    """A name matching aoss's ``^[a-z][a-z0-9-]+$`` within ``maxlen`` (policy 32, collection 64)."""
    raw = ctx.unique_name(prefix).lower()
    kept = "".join(ch if (ch.isalpha() and ch.isascii()) or ch.isdigit() or ch == "-" else "-"
                   for ch in raw)
    while "--" in kept:
        kept = kept.replace("--", "-")
    kept = kept.strip("-")
    if not kept or not kept[0].isalpha():
        kept = "a" + kept
    return kept[:maxlen].rstrip("-")


def _error(fn):
    """``(code, message)`` for a refused call. RAISES on unexpected success: returning a falsy
    sentinel would let an over-permissive target pass acceptance off as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected this call to be refused, but it succeeded with {result!r}")


def _delete_policy(ctx, policy_type: str, name: str) -> None:
    osc = ctx.client("opensearchserverless")
    try:
        osc.delete_security_policy(type=policy_type, name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_collection_when_stable(ctx, coll_id, timeout_s: float = _DELETE_BUDGET_S) -> None:
    """Teardown. DeleteCollection is refused while CREATING, so retry until accepted or already
    gone, and RAISE on exhaustion so a leak is reported rather than hidden."""
    if not coll_id:
        return
    osc = ctx.client("opensearchserverless")
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        try:
            osc.delete_collection(id=coll_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            last = code
        time.sleep(5.0)
    raise AssertionError(
        f"collection {coll_id} could not be deleted within {timeout_s}s (last {last!r}); it is "
        "LEAKED and still billing OCUs"
    )


def _wait_collection_active(ctx, coll_id: str, timeout_s: float = _ACTIVE_BUDGET_S) -> dict:
    osc = ctx.client("opensearchserverless")
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[coll_id])["collectionDetails"]
        if details:
            last = details[0]
            if last["status"] == "ACTIVE":
                return last
            if last["status"] in ("FAILED", "UPDATE_FAILED"):
                raise AssertionError(
                    f"collection {coll_id} entered {last['status']}: {last.get('failureMessage')!r}"
                )
        time.sleep(5.0)
    raise AssertionError(
        f"{STATE_MARKER}: collection {coll_id} never reached ACTIVE within {timeout_s}s (last "
        f"status {last.get('status')!r})"
    )


# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Encryption at rest is not optional on OpenSearch Serverless: CreateCollection with NEITHER an
    inline ``encryptionConfig`` NOR a matching encryption policy is a ValidationException naming
    encryption and creates nothing, while supplying EITHER route makes the identical call succeed.
    """
    osc = ctx.client("opensearchserverless")

    # --- POSITIVE CONTROL 1, first, so a refusal below can never be "CreateCollection is broken":
    # the inline encryptionConfig route, with NO encryption policy anywhere.
    inline_name = _aoss_name(ctx, "sim2real-aoss-enc-inline-", maxlen=64)
    inline_holder: dict[str, str] = {}
    ctx.on_cleanup(lambda: _delete_collection_when_stable(ctx, inline_holder.get("id")))
    inline_detail = osc.create_collection(
        name=inline_name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["createCollectionDetail"]
    inline_holder["id"] = inline_detail["id"]
    assert inline_detail["status"] == "CREATING", (
        f"expected a freshly created collection to report status CREATING, got "
        f"{inline_detail['status']!r}"
    )
    # Independent read, different operation than the mutation.
    seen = osc.batch_get_collection(names=[inline_name])["collectionDetails"]
    assert len(seen) == 1 and seen[0]["id"] == inline_holder["id"], (
        f"expected BatchGetCollection(names=[{inline_name!r}]) to return exactly the collection "
        f"just created ({inline_holder['id']!r}), got {seen!r}"
    )

    # --- THE REFUSAL: identical shape, minus encryptionConfig, with no matching policy.
    bare_name = _aoss_name(ctx, "sim2real-aoss-enc-bare-", maxlen=64)
    code, message = _error(
        lambda: osc.create_collection(
            name=bare_name, type="SEARCH", tags=[{"key": "sim2real", "value": CHECK}],
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for CreateCollection with neither encryptionConfig nor a "
        f"matching encryption policy, got {code!r} ({message!r})"
    )
    assert message == f"No matching security policy of encryption type found for collection name: {bare_name}. Please create security policy of encryption type for this collection.", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )
    lowered = message.lower()
    assert all(token in lowered for token in _ENCRYPTION_TOKENS), (
        f"expected the refusal message to name encryption (tokens {_ENCRYPTION_TOKENS}) so it is "
        f"separable from a malformed-name ValidationException, got {message!r}"
    )

    # --- EFFECT ABSENT, via an independent read.
    absent = osc.batch_get_collection(names=[bare_name])["collectionDetails"]
    assert absent == [], (
        f"expected no collection under the refused name {bare_name!r}, but BatchGetCollection "
        f"returned {absent!r}"
    )
    # ListCollections is asserted in BOTH directions, so an empty listing -- which would make an
    # absence-only assertion unfalsifiable -- fails on the presence half. Both calls are name-filtered
    # so neither depends on ListCollections' 20-item default page.
    present = [
        c["name"]
        for c in osc.list_collections(collectionFilters={"name": inline_name})["collectionSummaries"]
    ]
    assert present == [inline_name], (
        f"expected ListCollections filtered to {inline_name!r} (the collection that WAS created) to "
        f"return exactly that one name, got {present!r} -- without this the absence assertion below "
        "would hold against a target whose ListCollections always returns nothing"
    )
    absent_listing = [
        c["name"]
        for c in osc.list_collections(collectionFilters={"name": bare_name})["collectionSummaries"]
    ]
    assert absent_listing == [], (
        f"expected ListCollections filtered to the refused name {bare_name!r} to return nothing, got "
        f"{absent_listing!r}"
    )

    # --- DISCRIMINATOR: a DIFFERENT invalid input under the same operation must produce a
    # DIFFERENT message, so the check cannot pass against a target that refuses every
    # CreateCollection with one canned ValidationException. `_MALFORMED_NAME` violates
    # CollectionName's ^[a-z][a-z0-9-]+$ pattern but satisfies its length trait, so botocore cannot
    # reject it locally and the SERVICE has to answer -- a ParamValidationError here would mean the
    # request never left the SDK and would assert nothing.
    other_code, other_message = _error(
        lambda: osc.create_collection(
            name=_MALFORMED_NAME, type="SEARCH", encryptionConfig={"aWSOwnedKey": True},
        )
    )
    assert other_code == "ValidationException", (
        f"expected ValidationException for an illegal collection name, got {other_code!r} "
        f"({other_message!r})"
    )
    assert other_message == "1 validation error detected: Value '1-invalid-collection-name' at 'name' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-z][a-z0-9_-]+", (
        f"expected the exact ValidationException message AWS returns, got {other_message!r}"
    )
    assert other_message != message, (
        "expected the malformed-name refusal and the missing-encryption refusal to carry DIFFERENT "
        f"messages; both said {message!r}, so this target refuses CreateCollection generically "
        "rather than diagnosing the encryption requirement"
    )

    # --- RESTORE: create the matching encryption policy and re-issue the BYTE-IDENTICAL call.
    enc_name = _aoss_name(ctx, "sim2real-aoss-enc-")
    osc.create_security_policy(
        type="encryption",
        name=enc_name,
        policy=json.dumps({
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{bare_name}"]}],
            "AWSOwnedKey": True,
        }),
    )
    ctx.on_cleanup(lambda: _delete_policy(ctx, "encryption", enc_name))

    bare_holder: dict[str, str] = {}
    ctx.on_cleanup(lambda: _delete_collection_when_stable(ctx, bare_holder.get("id")))
    restored = osc.create_collection(
        name=bare_name, type="SEARCH", tags=[{"key": "sim2real", "value": CHECK}],
    )["createCollectionDetail"]
    bare_holder["id"] = restored["id"]

    # --- TERMINAL READ: the restored collection actually comes up, and the encryption the policy
    # promised is reported back by a DIFFERENT operation than the one that created it. No key ARN
    # SHAPE is pinned -- an AWSOwnedKey policy reports the literal sentinel "auto" here, not a real
    # ARN -- only that the service populated the field at all.
    final = _wait_collection_active(ctx, bare_holder["id"])
    assert final["name"] == bare_name, (
        f"expected the ACTIVE collection to be named {bare_name!r}, got {final['name']!r}"
    )
    kms_key_arn = final.get("kmsKeyArn")
    assert isinstance(kms_key_arn, str) and len(kms_key_arn) > 0, (
        f"expected the collection created under an AWSOwnedKey encryption policy to report a "
        f"populated kmsKeyArn, got {kms_key_arn!r} -- encryption at rest is mandatory for every "
        "serverless collection (AWS docs, 'Encryption in Amazon OpenSearch Serverless')"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
