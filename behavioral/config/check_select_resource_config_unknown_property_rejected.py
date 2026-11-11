"""select-resource-config-unknown-property-rejected."""

from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

def _error_code_and_message(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


CHECK = "select-resource-config-unknown-property-rejected"
GROUP = 'resource-config'
SERVICES = ['config']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SelectResourceConfig accepts an unknown property (echoed in SelectFields, omitted from rows)
    but rejects unprojected GROUP BY, invalid aggregates and unknown functions with
    InvalidExpressionException and exact messages.
    """
    cfg = ctx.client("config")

    # Control: a valid aggregate with GROUP BY over a projected field is accepted.
    control = cfg.select_resource_config(
        Expression="SELECT resourceType, COUNT(*) GROUP BY resourceType"
    )
    control_fields = [f["Name"] for f in control["QueryInfo"]["SelectFields"]]
    assert control_fields == ["resourceType", "COUNT(*)"], (
        f"the control projection must be echoed verbatim and in order, got {control_fields!r}"
    )
    for row in control["Results"]:
        parsed = json.loads(row)
        assert "resourceType" in parsed and "COUNT(*)" in parsed, (
            f"each result row must carry exactly the projected keys, got {sorted(parsed)!r}"
        )

    # The analyser does not validate property names: the query is accepted, the unknown
    # name is echoed in the plan, and the key is dropped from the rows.
    unknown = "thisPropertyDoesNotExist"
    baseline = cfg.select_resource_config(Expression="SELECT resourceId")
    probed = cfg.select_resource_config(Expression=f"SELECT resourceId, {unknown}")
    probed_fields = [f["Name"] for f in probed["QueryInfo"]["SelectFields"]]
    assert probed_fields == ["resourceId", unknown], (
        f"an unknown configuration property is ACCEPTED by real AWS and echoed "
        f"verbatim in QueryInfo.SelectFields (measured); an emulator must neither "
        f"refuse it nor drop it from the plan, got {probed_fields!r}"
    )
    assert len(probed["Results"]) == len(baseline["Results"]), (
        f"an unknown property must not filter the result set -- the same query with "
        f"and without it must return the same number of rows; got "
        f"{len(probed['Results'])} vs baseline {len(baseline['Results'])}"
    )
    for row in probed["Results"]:
        parsed = json.loads(row)
        assert unknown not in parsed, (
            f"real AWS OMITS an unknown property from the row JSON rather than "
            f"returning it as a null-valued key; got {sorted(parsed)!r}"
        )
        assert "resourceId" in parsed, (
            f"the known sibling projection must still be present, got {sorted(parsed)!r}"
        )

    code, msg = _error_code_and_message(
        lambda: cfg.select_resource_config(
            Expression="SELECT resourceId GROUP BY resourceType"
        )
    )
    assert code == "InvalidExpressionException", (
        f"GROUP BY over an unprojected field must be refused with "
        f"InvalidExpressionException; got {code!r}"
    )
    assert msg == (
        "when a GROUP BY clause or Aggregate Function (AVG|COUNT|MAX|MIN|SUM) is "
        "present, selected fields (resourceId) must appear in the GROUP BY field list"
    ), (
        f"the refusal must name the offending selected field and the GROUP BY rule "
        f"so a caller can fix the query -- this is the distinguishing detail the "
        f"wire matcher drops ($.message is on match.ignore); got {msg!r}"
    )

    code, msg = _error_code_and_message(
        lambda: cfg.select_resource_config(Expression="SELECT SUM(resourceId)")
    )
    assert code == "InvalidExpressionException", (
        f"SUM over a string field must be refused with InvalidExpressionException; "
        f"got {code!r}"
    )
    assert msg == "Query is invalid.", f"expected the exact refusal message, got {msg!r}"

    # Unlike an unknown property, an unknown function is refused.
    code, msg = _error_code_and_message(
        lambda: cfg.select_resource_config(Expression="SELECT FROBNICATE(resourceId)")
    )
    assert code == "InvalidExpressionException", (
        f"an unknown aggregate function must be refused with "
        f"InvalidExpressionException even though an unknown PROPERTY is accepted; "
        f"got {code!r}"
    )
    assert msg == "field name FROBNICATE(resourceId) contains invalid characters", (
        f"real AWS reports an unknown function as a field-name character violation "
        f"(measured), not as an unknown-function error; got {msg!r}"
    )

    # The rejections must leave the query surface working.
    again = cfg.select_resource_config(
        Expression="SELECT resourceType, COUNT(*) GROUP BY resourceType"
    )
    assert [f["Name"] for f in again["QueryInfo"]["SelectFields"]] == control_fields, (
        f"rejected expressions must leave the engine unaffected; control projection "
        f"changed to {again['QueryInfo']['SelectFields']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
