"""apikey-decrypt-invalid-format-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "apikey-decrypt-invalid-format-rejected"
GROUP = 'apikey'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _error_stable(fn, attempts=10, delay=6.0):
    """(code, message) of the first non-transient failure, retrying throttling and propagation
    errors; a call that succeeds fails the check."""
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDecryptedAPIKey with a malformed key string is WAFInvalidParameterException, while a
    freshly created key decrypts to its token domains, so the refusal is format-specific."""
    w = ctx.client("wafv2")

    domain = f"{ctx.unique_name('sim2real-wafv2').replace('_', '-')}.example.com"
    created = w.create_api_key(Scope=SCOPE, TokenDomains=[domain])
    api_key = created["APIKey"]
    ctx.on_cleanup(lambda: w.delete_api_key(Scope=SCOPE, APIKey=api_key))

    # Positive control: a validly formatted key decrypts successfully.
    decrypted = w.get_decrypted_api_key(Scope=SCOPE, APIKey=api_key)
    assert decrypted["TokenDomains"] == [domain], decrypted

    code, message = _error_stable(
        lambda: w.get_decrypted_api_key(Scope=SCOPE, APIKey="not-a-real-waf-api-key")
    )
    assert code == "WAFInvalidParameterException", code
    assert message == "Error reason: The parameter contains formatting that is not valid., field: null, parameter: not-a-real-waf-api-key", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
