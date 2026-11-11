"""list-functions-unsupported-operation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-functions-unsupported-operation-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

# ListFunctions documents exactly two error codes: InvalidArgument and
# UnsupportedOperation ("This operation is not supported in this AWS
# Region."). The latter is a region/partition-availability restriction, not a
# parameter-validation error -- CloudFront Functions is available
# account-wide in every commercial-partition region/endpoint this harness can
# reach, and Stage's only legal values (DEVELOPMENT|LIVE) are enum-constrained
# in the SDK model, so a bogus Stage never reaches the wire (botocore raises
# ParamValidationError locally instead of exercising the service). There is no
# known, reachable way to force UnsupportedOperation from a standard
# commercial-partition credential. What IS reachable and exercises the same
# ListFunctions error-handling path is the other documented error,
# InvalidArgument, triggered by a MaxItems value AWS rejects server-side
# (MaxItems is a plain integer with no client-side enum/range validation, so
# this genuinely round-trips to the service instead of failing locally).


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFunctions rejects a non-positive MaxItems with InvalidArgument; a valid call still succeeds."""
    cf = ctx.client("cloudfront")

    # MaxItems is bound as a query-string parameter and modeled as a string
    # in the SDK (unlike e.g. ListConnectionFunctions' XML-body integer
    # MaxItems) -- a negative value round-trips to the service and is
    # rejected server-side.
    code, message = _error(lambda: cf.list_functions(MaxItems="-1"))
    assert code == "InvalidArgument", f"expected InvalidArgument for MaxItems='-1', got {code!r}"
    expected = "MaxItems must be a non-zero positive integer."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control in the same file: a well-formed call is not rejected,
    # and returns real, shape-checked response body content (not just a
    # non-error status) -- so this isn't a blanket "reject everything" stub.
    resp = cf.list_functions(MaxItems="5")
    function_list = resp["FunctionList"]
    assert "Items" in function_list, f"ListFunctions response missing 'Items': {function_list!r}"
    assert isinstance(function_list["Quantity"], int), (
        f"expected Quantity to be an int, got {function_list['Quantity']!r}"
    )
    assert function_list["Quantity"] == len(function_list["Items"]), (
        f"Quantity {function_list['Quantity']!r} != len(Items) {len(function_list['Items'])!r}"
    )
    for summary in function_list["Items"]:
        stage = summary["FunctionMetadata"]["Stage"]
        assert stage in ("DEVELOPMENT", "LIVE"), f"unexpected Stage {stage!r} on {summary!r}"

    # Stage filtering (still on the well-formed path): every item returned for
    # a given stage actually reports that stage.
    for stage in ("DEVELOPMENT", "LIVE"):
        filtered = cf.list_functions(Stage=stage)["FunctionList"]
        for summary in filtered["Items"]:
            assert summary["FunctionMetadata"]["Stage"] == stage, (
                f"ListFunctions(Stage={stage!r}) returned an item in stage "
                f"{summary['FunctionMetadata']['Stage']!r}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
