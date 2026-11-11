"""delete-apikey-nonexistent-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-apikey-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAPIKey with a never-issued token is WAFInvalidParameterException and removes no key;
    a real key deletes, after which GetDecryptedAPIKey is WAFNonexistentItemException."""
    wafv2 = ctx.client("wafv2")

    domain = ctx.unique_name("sim2real-behav-") + ".example.com"
    created = wafv2.create_api_key(Scope="REGIONAL", TokenDomains=[domain])
    real_key = created["APIKey"]
    ctx.on_cleanup(lambda: _best_effort_delete_api_key(wafv2, real_key))

    bogus_key = "sim2real-never-issued-api-key-token-000000000000"
    code, message = _error(
        lambda: wafv2.delete_api_key(Scope="REGIONAL", APIKey=bogus_key)
    )
    assert code == "WAFInvalidParameterException", (
        f"expected WAFInvalidParameterException deleting a never-issued API key token, got {code!r}"
    )
    assert message == (
        "Error reason: The parameter contains formatting that is not valid., field: null, "
        f"parameter: {bogus_key}"
    ), message

    # The rejected delete removed nothing: this check's own key is still listed, and the
    # never-issued token is not.
    listed = [s["APIKey"] for s in _summaries_for(wafv2, {domain})]
    assert listed == [real_key], (
        f"expected only this check's key listed for {domain} after the rejected delete, got {listed!r}"
    )
    assert bogus_key not in [s["APIKey"] for s in _summaries_for(wafv2, None)], (
        "the never-issued token is listed as an API key after the rejected delete"
    )

    # Positive control: the real key deletes cleanly.
    wafv2.delete_api_key(Scope="REGIONAL", APIKey=real_key)

    decode_code, decode_message = _error(
        lambda: wafv2.get_decrypted_api_key(Scope="REGIONAL", APIKey=real_key)
    )
    assert decode_code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException decrypting the just-deleted key, got {decode_code!r}"
    )
    assert decode_message == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", decode_message


def _summaries_for(wafv2, domains: set | None) -> list:
    """Every REGIONAL API key summary touching one of `domains` (all of them for None), across
    every page."""
    found, marker = [], None
    while True:
        kwargs = {"Scope": "REGIONAL", "Limit": 100}
        if marker:
            kwargs["NextMarker"] = marker
        page = wafv2.list_api_keys(**kwargs)
        found += [s for s in page.get("APIKeySummaries", [])
                  if domains is None or domains & set(s.get("TokenDomains", []))]
        marker = page.get("NextMarker")
        if not marker:
            return found


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected a ClientError, but the call succeeded and returned {result!r}"
    )


def _best_effort_delete_api_key(wafv2, key: str) -> None:
    try:
        wafv2.delete_api_key(Scope="REGIONAL", APIKey=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
