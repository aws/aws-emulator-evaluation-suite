"""create-collection-malformed-name-validation-rejected."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-collection-malformed-name-validation-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]

# CollectionName must match ^[a-z][a-z0-9-]+$ -- starting with a digit violates the pattern.
_MALFORMED_NAME = "1-invalid-collection-name"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCollection with a name that violates the required pattern (starts with a digit)
    is rejected with ValidationException and nothing is created, while a validly-named
    collection creates successfully (positive control) in the same run."""
    aoss = ctx.client("opensearchserverless")

    # negative: a malformed name is rejected before anything is provisioned
    code, message = _error(lambda: aoss.create_collection(name=_MALFORMED_NAME, type="SEARCH"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{_MALFORMED_NAME}' at 'name' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-z][a-z0-9_-]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: nothing was created under that (invalid) name. BatchGetCollection applies the
    # same CollectionName pattern to its own `names` argument, so it cannot be used to look up a
    # malformed name -- it would reject the lookup itself. ListCollections takes no name argument
    # to validate, so scan its (unfiltered) results instead.
    found = _find_collection_by_name(aoss, _MALFORMED_NAME)
    assert found is None, f"expected no collection named {_MALFORMED_NAME!r}, found {found!r}"

    # positive control: a validly-named collection creates successfully. AWS requires a matching
    # encryption security policy to exist before CreateCollection will accept any name at all
    # (ValidationException("No matching security policy of encryption type found...") otherwise),
    # so create one scoped to this collection's exact name first.
    valid_name = _short_name(ctx, "sim2real-validcol")
    policy_name = _short_name(ctx, "sim2real-encpol")
    enc_doc = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{valid_name}"]}],
        "AWSOwnedKey": True,
    }
    aoss.create_security_policy(type="encryption", name=policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_security_policy(type="encryption", name=policy_name)))

    created = aoss.create_collection(
        name=valid_name,
        type="SEARCH",
        standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": "malformed-name-validation-rejected"}],
    )["createCollectionDetail"]
    collection_id = created["id"]
    assert created["name"] == valid_name, f"expected name {valid_name!r}, got {created['name']!r}"
    ctx.on_cleanup(lambda: _delete_collection_when_stable(ctx, collection_id))


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


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


def _find_collection_by_name(client: Any, name: str) -> dict | None:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = client.list_collections(**kwargs)
        for summary in resp.get("collectionSummaries", []):
            if summary.get("name") == name:
                return summary
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _delete_collection_when_stable(ctx, collection_id, timeout_s=900.0, interval_s=15.0):
    client = ctx.client("opensearchserverless")

    def probe():
        resp = client.batch_get_collection(ids=[collection_id])
        details = resp.get("collectionDetails", [])
        return details[0]["status"] if details else "GONE"

    status = _poll_until(
        probe, lambda s: s in ("ACTIVE", "FAILED", "GONE"), timeout_s=timeout_s, interval_s=interval_s
    )
    if status == "GONE":
        return
    try:
        client.delete_collection(id=collection_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
