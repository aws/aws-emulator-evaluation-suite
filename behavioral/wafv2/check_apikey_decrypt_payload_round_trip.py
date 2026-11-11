"""apikey-decrypt-payload-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "apikey-decrypt-payload-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDecryptedAPIKey returns exactly the five TokenDomains given to CreateAPIKey, sorted
    lexicographically, with none dropped, added or altered."""
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"

    suffix = ctx.unique_name("sim2real-apikey-").rsplit("-", 1)[-1]
    token_domains = [
        f"app-{suffix}.example.com",
        f"example-{suffix}.org",
        f"test-domain-{suffix}.net",
        f"sub.domain-{suffix}.io",
        f"myapp-{suffix}.example-corp.com",
    ]

    created = wafv2.create_api_key(Scope=scope, TokenDomains=token_domains)
    api_key = created["APIKey"]
    ctx.on_cleanup(lambda: wafv2.delete_api_key(Scope=scope, APIKey=api_key))

    decrypted = wafv2.get_decrypted_api_key(Scope=scope, APIKey=api_key)
    got = decrypted["TokenDomains"]
    assert sorted(got) == sorted(token_domains), (
        f"TokenDomains value set changed on round trip: got {got}, "
        f"want {token_domains}"
    )
    # AWS normalizes to lexicographic order rather than preserving request order.
    assert got == sorted(token_domains), (
        f"expected AWS to return TokenDomains sorted lexicographically, got {got}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
