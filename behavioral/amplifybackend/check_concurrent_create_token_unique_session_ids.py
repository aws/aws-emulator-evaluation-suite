"""concurrent-create-token-unique-session-ids."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-create-token-unique-session-ids"
GROUP = "concurrency"
SERVICES = ["amplifybackend"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateToken calls for the same app each mint a distinct, independently valid session."""
    app_id = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    n = 8

    def _create():
        return ab.create_token(AppId=app_id)

    results = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_create) for _ in range(n)]
        for fut in as_completed(futures):
            results.append(fut.result())

    session_ids = [r["SessionId"] for r in results]
    assert len(session_ids) == n, f"expected {n} concurrent CreateToken results, got {len(session_ids)}"
    assert len(set(session_ids)) == n, "CreateToken issued duplicate session ids under contention"

    for r in results:
        ctx.on_cleanup(lambda sid=r["SessionId"]: ab.delete_token(AppId=app_id, SessionId=sid))
        fetched = ab.get_token(AppId=app_id, SessionId=r["SessionId"])
        assert fetched["ChallengeCode"] == r["ChallengeCode"], (
            f"expected ChallengeCode {r['ChallengeCode']!r}, GetToken returned {fetched.get('ChallengeCode')!r}"
        )


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    resp = amplify.create_app(name=ctx.unique_name("sim2real-ab-app-"), tags={"sim2real": CHECK})
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
    return app_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
