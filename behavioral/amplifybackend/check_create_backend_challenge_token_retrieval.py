"""create-backend-challenge-token-retrieval."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-backend-challenge-token-retrieval"
GROUP = "state"
SERVICES = ["amplifybackend"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateToken returns a challenge session whose AppId, SessionId and ChallengeCode GetToken
    returns unchanged, while GetToken's Ttl comes back as an empty string."""
    app_id = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")

    created = ab.create_token(AppId=app_id)
    session_id = created["SessionId"]
    challenge_code = created["ChallengeCode"]
    ttl = created["Ttl"]
    assert created["AppId"] == app_id
    assert session_id and challenge_code and ttl
    ctx.on_cleanup(lambda: ab.delete_token(AppId=app_id, SessionId=session_id))

    fetched = ab.get_token(AppId=app_id, SessionId=session_id)
    assert fetched["AppId"] == app_id
    assert fetched["SessionId"] == session_id
    assert fetched["ChallengeCode"] == challenge_code
    # GetToken's Ttl field is not populated with the original TTL.
    assert fetched["Ttl"] == "", repr(fetched.get("Ttl"))


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    resp = amplify.create_app(name=ctx.unique_name("sim2real-ab-app-"))
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
    return app_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
