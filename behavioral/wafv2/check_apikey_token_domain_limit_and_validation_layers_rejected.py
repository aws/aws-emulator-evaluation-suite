"""apikey-token-domain-limit-and-validation-layers-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apikey-token-domain-limit-and-validation-layers-rejected"
GROUP = "validation"
SERVICES = ["wafv2"]

_MAX_DOMAINS = 5


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAPIKey fails for a sixth domain (WAFLimitsExceededException), a domain with a path
    (WAFInvalidParameterException, Field TOKEN_DOMAIN) and one with a scheme (ValidationException),
    each with its exact message and storing nothing, while five domains mint a key stored with them.
    """
    wafv2 = ctx.client("wafv2")
    # Short labels on purpose: the key encrypts the domain list, and five long domains overflow a
    # separate byte budget (API_KEY_KMS_DATA_BYTES_LENGTH) before the count limit is reached. Only
    # the unique tail of the run's name is kept, so concurrent runs still use disjoint domains.
    stem = ctx.unique_name("sim2real-").replace("_", "-").lower()[-8:]
    five = [f"d{i}-{stem}.example.com" for i in range(_MAX_DOMAINS)]
    six = five + [f"d{_MAX_DOMAINS}-{stem}.example.com"]
    with_path = f"p-{stem}.example.com/login"
    with_scheme = f"https://s-{stem}.example.com"
    ours = set(six) | {with_path, with_scheme}

    ctx.on_cleanup(lambda: _delete_keys_for(wafv2, ours))

    err = _error(lambda: wafv2.create_api_key(Scope="REGIONAL", TokenDomains=six))
    assert err["Code"] == "WAFLimitsExceededException", f"six domains: got {err!r}"
    assert err["Message"] == (
        "AWS WAF couldn’t perform the operation because you exceeded your resource limit "
        "NUM_TOKEN_DOMAINS_IN_API_KEY"
    ), f"six domains: message was {err['Message']!r}"

    err = _error(lambda: wafv2.create_api_key(Scope="REGIONAL", TokenDomains=[with_path]))
    assert err["Code"] == "WAFInvalidParameterException", f"domain with a path: got {err!r}"
    assert err["Message"] == (
        f"Error reason: The parameter contains formatting that is not valid., "
        f"field: TOKEN_DOMAIN, parameter: {with_path}"
    ), f"domain with a path: message was {err['Message']!r}"
    assert (err["Field"], err["Parameter"]) == ("TOKEN_DOMAIN", with_path), (
        f"domain with a path: the structured members must name the field and the value, "
        f"got Field={err['Field']!r} Parameter={err['Parameter']!r}"
    )

    err = _error(lambda: wafv2.create_api_key(Scope="REGIONAL", TokenDomains=[with_scheme]))
    assert err["Code"] == "ValidationException", f"domain with a scheme: got {err!r}"
    assert err["Message"] == (
        f"1 validation error detected: Value '[{with_scheme}]' at 'tokenDomains' failed to "
        f"satisfy constraint: Member must satisfy constraint: [Member must have length less "
        f"than or equal to 253, Member must have length greater than or equal to 1, Member must "
        f"satisfy regular expression pattern: ^[\\w\\.\\-/]+$]"
    ), f"domain with a scheme: message was {err['Message']!r}"

    # POSITIVE CONTROL: the documented ceiling itself is accepted.
    key = wafv2.create_api_key(Scope="REGIONAL", TokenDomains=five)["APIKey"]
    assert isinstance(key, str) and key, "five domains must mint a key"

    stored = sorted(sorted(s["TokenDomains"]) for s in _summaries_for(wafv2, ours))
    assert stored == [sorted(five)], (
        f"only the five-domain control may be stored; ListAPIKeys holds {stored!r} for this "
        f"check's domains"
    )


def _error(fn) -> dict:
    """The ClientError's response members (Code, Message, Field, Parameter); a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        body = exc.response
        return {"Code": body["Error"]["Code"], "Message": body["Error"].get("Message"),
                "Field": body.get("Field"), "Parameter": body.get("Parameter")}
    raise AssertionError(f"expected CreateAPIKey to be refused, but it succeeded: "
                         f"{sorted(result)!r}")


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
    """Delete every key minted for this check's domains; a key already gone is tolerated."""
    for summary in _summaries_for(wafv2, domains):
        try:
            wafv2.delete_api_key(Scope="REGIONAL", APIKey=summary["APIKey"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
