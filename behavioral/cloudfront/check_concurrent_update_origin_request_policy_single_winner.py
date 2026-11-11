"""concurrent-update-origin-request-policy-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-origin-request-policy-single-winner"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateOriginRequestPolicy calls from the same ETag: exactly one succeeds, the
    other is rejected as a stale ETag, and the persisted state matches the winner."""
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")

    name = ctx.unique_name("sim2real-orp-race-")
    create_resp = cf.create_origin_request_policy(
        OriginRequestPolicyConfig={
            "Comment": "initial",
            "Name": name,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        }
    )
    policy_id = create_resp["OriginRequestPolicy"]["Id"]
    etag = create_resp["ETag"]
    ctx.on_cleanup(lambda: _delete_policy(ctx, policy_id))

    def update_with(comment: str):
        return cf.update_origin_request_policy(
            Id=policy_id,
            IfMatch=etag,
            OriginRequestPolicyConfig={
                "Comment": comment,
                "Name": name,
                "HeadersConfig": {"HeaderBehavior": "none"},
                "CookiesConfig": {"CookieBehavior": "none"},
                "QueryStringsConfig": {"QueryStringBehavior": "none"},
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(update_with, "winner-a")
        fut_b = pool.submit(update_with, "winner-b")
        results = []
        for fut, tag in ((fut_a, "a"), (fut_b, "b")):
            try:
                resp = fut.result()
                results.append((tag, "ok", resp))
            except ClientError as exc:
                results.append((tag, exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    oks = [r for r in results if r[1] == "ok"]
    fails = [r for r in results if r[1] != "ok"]
    assert len(oks) == 1, f"expected exactly one winner, got {results}"
    assert len(fails) == 1, f"expected exactly one loser, got {results}"
    # A syntactically well-formed but now-stale ETag is a precondition failure
    # (HTTP 412), not a malformed/missing If-Match header (InvalidIfMatchVersion).
    assert fails[0][1] in ("PreconditionFailed", "InvalidIfMatchVersion"), (
        f"expected the loser to be rejected with PreconditionFailed or InvalidIfMatchVersion, "
        f"got {fails[0][1]}"
    )
    if fails[0][1] == "PreconditionFailed":
        assert fails[0][2] == "The request failed because it didn't meet the preconditions for this operation.", (
            f"UpdateOriginRequestPolicy PreconditionFailed message: {fails[0][2]!r}"
        )

    winner_comment = "winner-a" if oks[0][0] == "a" else "winner-b"
    final = cf.get_origin_request_policy(Id=policy_id)["OriginRequestPolicy"][
        "OriginRequestPolicyConfig"
    ]
    assert final["Comment"] == winner_comment, (
        f"final state {final['Comment']!r} does not match the actual winner "
        f"{winner_comment!r} -- update was not atomic"
    )


def _delete_policy(ctx, policy_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_origin_request_policy(Id=policy_id)["ETag"]
    cf.delete_origin_request_policy(Id=policy_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
