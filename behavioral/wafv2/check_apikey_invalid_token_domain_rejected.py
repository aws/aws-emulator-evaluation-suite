"""apikey-invalid-token-domain-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "apikey-invalid-token-domain-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _error_stable(fn, attempts=10, delay=6.0):
    """Return (code, message) of the first NON-transient failure. Transient WAFv2 codes
    are retried rather than reported, so an assertion about a semantic error is never
    polluted by throttling or propagation delay. A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            code, message = "", ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
                message = resp.get("Error", {}).get("Message", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, message
            time.sleep(delay)
        else:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    raise AssertionError("unreachable")

def _error_code_stable_ok(fn, attempts=10, delay=6.0):
    """Retry a call that is expected to succeed through WAFv2's transient
    control-plane codes, raising on the first non-transient failure."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in _TRANSIENT_CODES:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
    raise last_exc

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAPIKey with a TokenDomain that is not a valid domain name fails with
    ValidationException and the exact message and adds no key to ListAPIKeys, while a valid domain
    mints a key that ListAPIKeys returns."""
    w = ctx.client("wafv2")

    code, message = _error_stable(
        lambda: w.create_api_key(Scope=SCOPE, TokenDomains=["not a domain!!"])
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value '[not a domain!!]' at 'tokenDomains' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must have length less than "
        "or equal to 253, Member must have length greater than or equal to 1, Member must satisfy "
        r"regular expression pattern: ^[\w\.\-/]+$]"
    ), message

    minted = _summaries_for(w, {"not a domain!!"})
    assert minted == [], f"the refused TokenDomain still minted a key: {minted!r}"

    # Positive control, same wiring: a well-formed TokenDomain succeeds and
    # becomes visible in an independent read.
    domain = f"{ctx.unique_name('sim2real-wafv2').replace('_', '-')}.example.com"
    created = _error_code_stable_ok(
        lambda: w.create_api_key(Scope=SCOPE, TokenDomains=[domain])
    )
    api_key = created["APIKey"]
    ctx.on_cleanup(lambda: w.delete_api_key(Scope=SCOPE, APIKey=api_key))

    listed = _summaries_for(w, {domain})
    assert api_key in [s["APIKey"] for s in listed], listed

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
