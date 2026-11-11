"""concurrent-create-scope-same-target-one-wins."""
from __future__ import annotations

import re

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-scope-same-target-one-wins"
GROUP = "concurrency"
SERVICES = ["networkflowmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """Two concurrent CreateScope calls for one target never both succeed: with no scope yet exactly
    one wins with that target; with the Region's one scope already present neither does and its
    targets stay unchanged; each loser gets ServiceQuotaExceededException with the exact message."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    target = {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": ctx.region}
    resource_tags = {"sim2real-owner": "behavioral-suite"}

    pre_existing = nfm.list_scopes().get("scopes", [])
    existing_before = nfm.get_scope(scopeId=pre_existing[0]["scopeId"]) if pre_existing else None

    def attempt():
        try:
            resp = nfm.create_scope(targets=[target], tags=resource_tags)
            return ("ok", resp["scopeId"], None)
        except ClientError as err:
            # AWS appends a per-call request id to the ServiceQuotaExceededException text; the
            # rest names the caller's account and is graded exactly below.
            return ("error", err.response["Error"]["Code"], _without_request_suffix(err.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))

    for kind, value, _ in results:
        if kind == "ok":
            ctx.on_cleanup(lambda scope_id=value: _delete_scope_and_wait(nfm, scope_id))

    outcomes = [r[0] for r in results]
    errors = [r[1] for r in results if r[0] == "error"]
    error_messages = [r[2] for r in results if r[0] == "error"]
    quota_message = f"Maximum limit of [1] for resource [scope] exceeded for account [{account_id}]."

    if existing_before is not None:
        # The singleton slot is already occupied: neither concurrent call can create a second scope.
        assert outcomes.count("ok") == 0, f"expected no winner on a non-cold account, got {results}"
        assert all(e == "ServiceQuotaExceededException" for e in errors), (
            f"expected ServiceQuotaExceededException from both concurrent calls, got {errors}"
        )
        assert error_messages == [quota_message, quota_message], (
            f"expected {quota_message!r} from both concurrent calls, got {error_messages!r}"
        )
        existing_after = nfm.get_scope(scopeId=existing_before["scopeId"])
        assert existing_after["targets"] == existing_before["targets"], (
            f"existing scope's targets changed after two rejected concurrent creates: "
            f"before={existing_before['targets']}, after={existing_after['targets']}"
        )
    else:
        assert outcomes.count("ok") == 1, f"expected exactly one winner, got {results}"
        assert outcomes.count("error") == 1, f"expected exactly one loser, got {results}"
        assert errors[0] == "ServiceQuotaExceededException", (
            f"expected ServiceQuotaExceededException for the loser, got {errors}"
        )
        assert error_messages == [quota_message], (
            f"expected {quota_message!r} for the loser, got {error_messages!r}"
        )
        winner_scope_id = next(v for k, v, _ in results if k == "ok")
        final = nfm.get_scope(scopeId=winner_scope_id)
        assert final["targets"] == [target], f"expected winner's targets to be [{target}], got {final['targets']}"


def _delete_scope_and_wait(nfm, scope_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    try:
        nfm.delete_scope(scopeId=scope_id)
    except ClientError as err:
        if err.response["Error"]["Code"] in ("ResourceNotFoundException", "ConflictException", "ValidationException"):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = nfm.get_scope(scopeId=scope_id)["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "DEACTIVATED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"scope {scope_id} did not fully deactivate within {timeout_s}s")


_REQUEST_SUFFIX = re.compile(
    r" \(Service: [A-Za-z0-9]+, Status Code: \d+, Request ID: [0-9a-fA-F-]+\)"
    r"( \(SDK Attempt Count: \d+\))?$"
)


def _without_request_suffix(message: str) -> str:
    """The message minus its per-request "(Service: ..., Request ID: ...) (SDK Attempt Count: n)"
    suffix, which is the only part that differs between calls."""
    return _REQUEST_SUFFIX.sub("", message or "")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

