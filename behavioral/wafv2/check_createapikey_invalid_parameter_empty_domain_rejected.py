"""createapikey-invalid-parameter-empty-domain-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "createapikey-invalid-parameter-empty-domain-rejected"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAPIKey with an empty TokenDomains list is rejected by the service with
    ValidationException (the modeled minItems=1 constraint enforced server-side) --
    a malformed-input class distinct from an individually-invalid domain value."""
    wafv2 = ctx.client("wafv2")

    # botocore's generated client validates the list's modeled minLength=1 locally
    # (raising ParamValidationError) before ever putting a request on the wire, so an
    # empty list never reaches the service through the normal client. The wired client
    # with local parameter validation disabled sends the empty list, so the service's own
    # validation runs.
    raw = ctx.client("wafv2", config=Config(parameter_validation=False))

    code, message = _error(lambda: raw.create_api_key(Scope="REGIONAL", TokenDomains=[]))
    assert code == "ValidationException", f"got {code!r} instead"
    assert message == (
        "1 validation error detected: Value '[]' at 'tokenDomains' failed to satisfy "
        "constraint: Member must have length greater than or equal to 1"
    ), message

    # Confirm no API key was created as a side effect of the rejected call.
    keys = wafv2.list_api_keys(Scope="REGIONAL")["APIKeySummaries"]
    assert not any(k.get("TokenDomains") == [] for k in keys), (
        f"expected no api key with an empty TokenDomains list, found one in {keys!r}"
    )

    # Positive control, same file: a well-formed CreateAPIKey call succeeds.
    domain = f"{ctx.unique_name('sim2real-wafv2').replace('_', '-')}.example.com"
    created = wafv2.create_api_key(Scope="REGIONAL", TokenDomains=[domain])
    api_key = created["APIKey"]
    ctx.on_cleanup(lambda: wafv2.delete_api_key(Scope="REGIONAL", APIKey=api_key))
    assert api_key, "CreateAPIKey returned no APIKey token"

    # Terminal assertion is an independent read at the destination (ListAPIKeys),
    # not the mutating call's own response: the well-formed key must actually be
    # visible with its domain, not merely echoed back.
    listed = wafv2.list_api_keys(Scope="REGIONAL")["APIKeySummaries"]
    match = next((k for k in listed if k.get("APIKey") == api_key), None)
    assert match is not None, f"created api key {api_key!r} not found via ListAPIKeys"
    assert match.get("TokenDomains") == [domain], (
        f"expected TokenDomains {[domain]!r}, got {match.get('TokenDomains')!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn raises; a success raises. No
    ParamValidationError branch: fn() runs on the client with local validation disabled,
    so such a raise means the empty list never left the SDK and must fail loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
