"""select-resource-config-limit-and-next-token-rejected."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

def _error(fn):
    """Return (code, message) of fn()'s ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


CHECK = "select-resource-config-limit-and-next-token-rejected"
GROUP = 'resource-config'
SERVICES = ['config']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SelectResourceConfig rejects Limit=101 with a ValidationException naming 'limit' and its 100
    ceiling, and a forged NextToken with InvalidNextTokenException, without clamping or restarting.
    """
    cfg = ctx.client("config")
    valid_expression = "SELECT resourceId, resourceType WHERE resourceType = 'AWS::S3::Bucket'"

    # Control: the identical expression at the modeled maximum must be accepted,
    # and the response must carry the projection the expression asked for. This
    # is what makes the two rejections below meaningful rather than "Select is
    # broken in this account".
    ok = cfg.select_resource_config(Expression=valid_expression, Limit=100)
    fields = [f["Name"] for f in ok["QueryInfo"]["SelectFields"]]
    assert fields == ["resourceId", "resourceType"], (
        f"control Select must project exactly the selected fields in order, got {fields!r}"
    )
    assert isinstance(ok["Results"], list), ok

    # Limit one past the maximum of 100 hits the generic range ValidationException, not the
    # operation's modeled InvalidLimitException, so the message is pinned too.
    code, message = _error(
        lambda: cfg.select_resource_config(Expression=valid_expression, Limit=101)
    )
    assert code == "ValidationException", (
        f"Limit=101 is one past the modeled maximum (0..100) and must be refused; "
        f"real AWS uses the generic range enforcer (ValidationException), not the "
        f"operation's own InvalidLimitException; got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value '101' at 'limit' failed to satisfy "
        "constraint: Member must have value less than or equal to 100"
    ), (
        f"the refusal must name the offending member and its ceiling -- "
        f"ValidationException alone is what every over-range member yields, so the "
        f"message is the only thing that proves Limit specifically was validated; "
        f"got {message!r}"
    )

    # ...and the refusal must not have been a clamp: the boundary value still works.
    boundary = cfg.select_resource_config(Expression=valid_expression, Limit=1)
    assert len(boundary["Results"]) <= 1, (
        f"Limit=1 must bound the page to at most one row, got {len(boundary['Results'])}"
    )

    # Break exactly one thing: a structurally plausible but forged NextToken.
    forged = ctx.unique_name("sim2real-behav-cfg-forged-token-")
    code, message = _error(
        lambda: cfg.select_resource_config(Expression=valid_expression, NextToken=forged)
    )
    assert code == "InvalidNextTokenException", (
        f"a forged NextToken must be refused with InvalidNextTokenException, never "
        f"silently ignored (which would restart the scan and duplicate rows); got {code!r}"
    )
    assert message == "The nextToken provided is invalid", (
        f"expected the exact invalid-token message, got {message!r}"
    )

    # Effect absent: the forged token must not have advanced or consumed any
    # server-side cursor -- the control expression still returns the same
    # projection and is still paginable from the start.
    after = cfg.select_resource_config(Expression=valid_expression, Limit=100)
    assert [f["Name"] for f in after["QueryInfo"]["SelectFields"]] == fields, (
        f"a rejected NextToken must leave query state untouched; projection changed to "
        f"{after['QueryInfo']['SelectFields']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
