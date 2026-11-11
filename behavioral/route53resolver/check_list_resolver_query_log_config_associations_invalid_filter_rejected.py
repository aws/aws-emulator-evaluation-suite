"""list-resolver-query-log-config-associations-invalid-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resolver-query-log-config-associations-invalid-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListResolverQueryLogConfigAssociations with an unsupported filter Name is refused with
    InvalidParameterException ("[RSLVR-01004] The filter key ... is invalid."), while a supported
    filter returns a list.
    """
    r53 = ctx.client("route53resolver")

    bogus_filter = [{"Name": "NotARealResolverFilterName", "Values": ["whatever"]}]

    code, message = _error(lambda: r53.list_resolver_query_log_config_associations(Filters=bogus_filter))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected = '[RSLVR-01004] The filter key "NotARealResolverFilterName" is invalid.'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control in the same file: a *valid* filter name on the same
    # operation must still succeed (proves the emulator isn't just rejecting
    # every call to this operation, which would make the negative above hollow).
    valid_resp = r53.list_resolver_query_log_config_associations(
        Filters=[{"Name": "Status", "Values": ["CREATED"]}]
    )
    assert "ResolverQueryLogConfigAssociations" in valid_resp, (
        f"expected ResolverQueryLogConfigAssociations key in response, got keys {sorted(valid_resp)!r}"
    )
    associations = valid_resp["ResolverQueryLogConfigAssociations"]
    assert isinstance(associations, list), f"expected a list, got {type(associations).__name__}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
