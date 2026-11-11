"""e2e-apikey-generate-decrypt-then-delete-invalidates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-apikey-generate-decrypt-then-delete-invalidates"
GROUP = "e2e"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDecryptedAPIKey returns a created key's TokenDomains, fails with WAFNonexistentItemException and
    the exact message after DeleteAPIKey, and still resolves a second, live key.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    domain = f"{ctx.unique_name('sim2real-behav-apikey-')}.example.com"

    created = wafv2.create_api_key(Scope=scope, TokenDomains=[domain])
    api_key = created["APIKey"]

    decrypted = wafv2.get_decrypted_api_key(Scope=scope, APIKey=api_key)
    assert decrypted["TokenDomains"] == [domain], (
        f"decrypted key's TokenDomains {decrypted['TokenDomains']!r} != created {[domain]!r}"
    )

    # Positive control: a second, still-live key must remain decryptable throughout.
    control_domain = f"{ctx.unique_name('sim2real-behav-apikey-ctrl-')}.example.com"
    control_created = wafv2.create_api_key(Scope=scope, TokenDomains=[control_domain])
    control_key = control_created["APIKey"]
    ctx.on_cleanup(lambda: wafv2.delete_api_key(Scope=scope, APIKey=control_key))

    wafv2.delete_api_key(Scope=scope, APIKey=api_key)

    code, message = _error(lambda: wafv2.get_decrypted_api_key(Scope=scope, APIKey=api_key))
    assert code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException decrypting a deleted key, got {code!r}"
    )
    assert message == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", message

    # The control key is unaffected by the deletion of the first key.
    control_decrypted = wafv2.get_decrypted_api_key(Scope=scope, APIKey=control_key)
    assert control_decrypted["TokenDomains"] == [control_domain], (
        f"control key's TokenDomains {control_decrypted['TokenDomains']!r} != "
        f"{[control_domain]!r} after deleting the unrelated first key"
    )


def _error(fn) -> tuple[str, str]:
    """Return (code, message) of the ClientError fn raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
