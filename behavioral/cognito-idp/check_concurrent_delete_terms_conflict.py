"""concurrent-delete-terms-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-delete-terms-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTerms racing with concurrent UpdateTerms on the same resource never leaves it
    partially applied: losers get ConcurrentModificationException or ResourceNotFoundException
    (once deleted), and afterwards the terms document is either fully gone or fully intact."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-")
    )["UserPoolClient"]["ClientId"]

    state: dict[str, str] = {}

    def _ensure_terms():
        if "terms_id" in state:
            try:
                idp.describe_terms(UserPoolId=pool_id, TermsId=state["terms_id"])
                return
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        resp = idp.create_terms(
            UserPoolId=pool_id,
            ClientId=client_id,
            TermsName="terms-of-use",
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": "https://example.com/terms-initial"},
        )
        state["terms_id"] = resp["Terms"]["TermsId"]

    # Real Cognito surfaces a losing writer in this race either as
    # ConcurrentModificationException or as ResourceNotFoundException (once the delete has
    # won and the document is gone for every later caller).
    for attempt in range(3):
        _ensure_terms()
        terms_id = state["terms_id"]
        fns = [
            (lambda tid=terms_id: idp.delete_terms(UserPoolId=pool_id, TermsId=tid))
            for _ in range(3)
        ] + [
            (lambda i=i, tid=terms_id, attempt=attempt: idp.update_terms(
                UserPoolId=pool_id,
                TermsId=tid,
                TermsName="terms-of-use",
                TermsSource="LINK",
                Enforcement="NONE",
                Links={"cognito:default": f"https://example.com/terms-{attempt}-{i}"},
            ))
            for i in range(5)
        ]
        results = _race(fns)
        successes = [r for r, err, _msg in results if err is None]
        others = [
            (err, msg) for _, err, msg in results if err is not None and not _is_conflict_loser(err)
        ]
        assert not others, f"unexpected errors racing delete/update terms: {others}"
        assert len(successes) >= 1, "no delete/update call succeeded under contention"
        if any(_is_conflict_loser(err) for _, err, _msg in results if err is not None):
            break
    else:
        raise AssertionError(
            "no ConcurrentModificationException/ResourceNotFoundException observed across"
            " 3 attempts of racing DeleteTerms against UpdateTerms"
        )

    try:
        final = idp.describe_terms(UserPoolId=pool_id, TermsId=state["terms_id"])["Terms"]
        assert final["Links"]["cognito:default"].startswith("https://example.com/terms"), (
            f"terms document survived the race with an unexpected Links value: {final['Links']!r}"
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            "terms document left in an unexpected error state after the race"
        )
        message = e.response["Error"].get("Message", "")
        assert message == "Terms does not exist.", (
            f"expected the exact deleted-terms message, got {message!r}"
        )


from botocore.exceptions import ClientError


def _call(fn):
    try:
        return fn(), None, None
    except ClientError as e:
        return None, e.response["Error"]["Code"], e.response["Error"].get("Message", "")


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(_call, fn) for fn in fns]
        return [f.result() for f in futures]


def _is_conflict_loser(code: str) -> bool:
    """True if `code` represents a legitimate losing-writer outcome for this race:
    ConcurrentModificationException, or ResourceNotFoundException (the resource was deleted
    by a winning racer)."""
    return code in ("ConcurrentModificationException", "ResourceNotFoundException")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
