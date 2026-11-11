"""apikey-decrypted-value-byte-equal-to-generated."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "apikey-decrypted-value-byte-equal-to-generated"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TokenDomains that GetDecryptedAPIKey recovers from a new CreateAPIKey key equal the requested
    domains byte for byte; order is not documented (AWS sorts them), so it is compared as a set.
    """
    wafv2 = ctx.client("wafv2")
    token_domains = ["sub.example.com", "example.com"]

    created = wafv2.create_api_key(Scope="REGIONAL", TokenDomains=token_domains)
    api_key = created["APIKey"]
    assert isinstance(api_key, str) and api_key, created
    ctx.on_cleanup(lambda: wafv2.delete_api_key(Scope="REGIONAL", APIKey=api_key))

    decrypted = wafv2.get_decrypted_api_key(Scope="REGIONAL", APIKey=api_key)
    got = decrypted["TokenDomains"]
    assert got == sorted(token_domains) or sorted(got) == sorted(token_domains), (
        f"expected byte-exact TokenDomains {sorted(token_domains)!r} in any order, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
