"""put-aggregation-authorization-malformed-account-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-aggregation-authorization-malformed-account-rejected"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "identity:standalone", "phase:standalone", "plane:control", "resource:account-singleton:config-aggregation-authorization")
def run(ctx) -> None:
    """PutAggregationAuthorization rejects a malformed (non-12-digit) account ID and
    creates no authorization record, while a well-formed authorization still succeeds.
    """
    cfg = ctx.client("config")
    region = ctx.region

    # The caller's own account: an authorization never names an account that might be someone's.
    valid_account = ctx.account
    cfg.put_aggregation_authorization(
        AuthorizedAccountId=valid_account,
        AuthorizedAwsRegion=region,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: cfg.delete_aggregation_authorization(
            AuthorizedAccountId=valid_account, AuthorizedAwsRegion=region
        )
    )

    listed = _all_authorizations(cfg)
    assert any(
        a["AuthorizedAccountId"] == valid_account and a["AuthorizedAwsRegion"] == region
        for a in listed
    )

    malformed_account = "not-an-account-id"
    code, message = _error(
        lambda: cfg.put_aggregation_authorization(
            AuthorizedAccountId=malformed_account, AuthorizedAwsRegion=region
        )
    )
    # AuthorizedAccountId must match `\d{12}`; the documented error is
    # InvalidParameterValueException, but real AWS's current Smithy-generated validation layer
    # surfaces this as ValidationException instead.
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    # AWS lists the two violations in either order from one call to the next, so the
    # message is compared as its exact header plus the exact set of violations.
    header = "2 validation errors detected: "
    assert message[: len(header)] == header, message
    violation = (
        f"Value '{malformed_account}' at 'authorizedAccountId' failed to satisfy constraint: "
    )
    assert sorted(message[len(header) :].split("; ")) == sorted(
        [
            violation + "Member must satisfy regular expression pattern: \\d{12}",
            violation + "Member must have length less than or equal to 12",
        ]
    ), message

    listed_after = _all_authorizations(cfg)
    assert not any(a["AuthorizedAccountId"] == malformed_account for a in listed_after)
    assert any(
        a["AuthorizedAccountId"] == valid_account and a["AuthorizedAwsRegion"] == region
        for a in listed_after
    )


def _all_authorizations(cfg):
    out = []
    next_token = None
    for _ in range(100):
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        page = cfg.describe_aggregation_authorizations(**kwargs)
        out.extend(page.get("AggregationAuthorizations", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    return out


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
