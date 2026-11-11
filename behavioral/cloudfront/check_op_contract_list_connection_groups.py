"""op-contract-listConnectionGroups."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listConnectionGroups"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnectionGroups returns a well-shaped list; a malformed AssociationFilter yields InvalidArgument."""
    cf = ctx.client("cloudfront")

    resp = cf.list_connection_groups()
    assert "ConnectionGroups" in resp, f"ListConnectionGroups response missing ConnectionGroups: {resp}"
    groups = resp["ConnectionGroups"]
    assert isinstance(groups, list), f"expected ConnectionGroups to be a list, got {type(groups)}"
    for g in groups:
        assert isinstance(g.get("Id"), str) and g["Id"], f"connection group summary missing Id: {g}"
        assert isinstance(g.get("RoutingEndpoint"), str) and g["RoutingEndpoint"], (
            f"connection group summary missing RoutingEndpoint: {g}"
        )

    code, msg = _error(
        lambda: cf.list_connection_groups(
            AssociationFilter={"AnycastIpListId": "not a valid id !!"}
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code}"
    assert msg == "The association filter id is invalid.", f"unexpected InvalidArgument message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
