"""apikey-create-idempotent-on-domain-set."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apikey-create-idempotent-on-domain-set"
GROUP = "concurrency"
SERVICES = ["wafv2"]

_CONCURRENT_CALLS = 5


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAPIKey returns one identical key for repeated, reordered and five concurrent calls with
    one token-domain set and a different key for another set; ListAPIKeys holds one Version 1
    summary per set, and deleting the shared key leaves only the other set's summary.
    """
    wafv2 = ctx.client("wafv2")
    stem = ctx.unique_name("sim2real-behav-wafkey-").replace("_", "-").lower()
    domain_a = f"a-{stem}.example.com"
    domain_b = f"b-{stem}.example.com"
    lone = f"c-{stem}.example.com"
    ours = {domain_a, domain_b, lone}

    # Cleanup first, by listing: every key this check could have minted carries one of its own
    # domains, so the net deletes all of them even if the target minted more than AWS does.
    ctx.on_cleanup(lambda: _delete_keys_for(wafv2, ours))

    first = wafv2.create_api_key(Scope="REGIONAL", TokenDomains=[domain_a, domain_b])["APIKey"]
    assert isinstance(first, str) and first, f"CreateAPIKey returned no key: {first!r}"

    again = wafv2.create_api_key(Scope="REGIONAL", TokenDomains=[domain_a, domain_b])["APIKey"]
    assert again == first, (
        f"repeating CreateAPIKey with the same domains returned a different key "
        f"(lengths {len(first)} and {len(again)}); AWS returns the byte-identical key"
    )

    reordered = wafv2.create_api_key(Scope="REGIONAL", TokenDomains=[domain_b, domain_a])["APIKey"]
    assert reordered == first, (
        "CreateAPIKey with the same two domains in the opposite order returned a different key; "
        "AWS keys the API key on the domain SET, not on the request order"
    )

    with ThreadPoolExecutor(max_workers=_CONCURRENT_CALLS) as pool:
        raced = list(pool.map(
            lambda _: wafv2.create_api_key(Scope="REGIONAL", TokenDomains=[lone])["APIKey"],
            range(_CONCURRENT_CALLS)))
    assert len(set(raced)) == 1, (
        f"{_CONCURRENT_CALLS} concurrent CreateAPIKey calls for one domain set returned "
        f"{len(set(raced))} distinct keys; AWS returns exactly one"
    )
    assert raced[0] != first, "a different domain set must mint a different key"

    summaries = _summaries_for(wafv2, ours)
    stored = sorted((sorted(s["TokenDomains"]), s["APIKey"] == first, s["APIKey"] == raced[0])
                    for s in summaries)
    assert stored == [
        ([domain_a, domain_b], True, False),
        ([lone], False, True),
    ], (
        f"ListAPIKeys must hold exactly one summary per domain set this check used, each naming "
        f"the key CreateAPIKey returned; got (domains, is-first-key, is-raced-key) {stored!r}"
    )
    by_key = {s["APIKey"]: s for s in summaries}
    assert by_key[first]["Version"] == 1 and by_key[raced[0]]["Version"] == 1, (
        f"a key minted once and re-requested stays at Version 1; got "
        f"{[s['Version'] for s in summaries]!r}"
    )

    decrypted = wafv2.get_decrypted_api_key(Scope="REGIONAL", APIKey=first)
    assert decrypted["TokenDomains"] == sorted([domain_a, domain_b]), (
        f"the idempotent key must decrypt to the two domains, got {decrypted['TokenDomains']!r}"
    )

    wafv2.delete_api_key(Scope="REGIONAL", APIKey=first)
    left = sorted(sorted(s["TokenDomains"]) for s in _summaries_for(wafv2, ours))
    assert left == [[lone]], (
        f"deleting the shared key must remove its single stored summary and nothing else; "
        f"ListAPIKeys still holds {left!r}"
    )


def _summaries_for(wafv2, domains: set) -> list:
    """Every REGIONAL API key summary touching one of `domains`, across every page."""
    found, marker = [], None
    while True:
        kwargs = {"Scope": "REGIONAL", "Limit": 100}
        if marker:
            kwargs["NextMarker"] = marker
        page = wafv2.list_api_keys(**kwargs)
        found += [s for s in page.get("APIKeySummaries", [])
                  if domains & set(s.get("TokenDomains", []))]
        marker = page.get("NextMarker")
        if not marker:
            return found


def _delete_keys_for(wafv2, domains: set) -> None:
    """Delete every key this check minted; a key already gone is the only tolerated error."""
    for summary in _summaries_for(wafv2, domains):
        try:
            wafv2.delete_api_key(Scope="REGIONAL", APIKey=summary["APIKey"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
