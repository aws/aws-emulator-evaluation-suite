"""parameter-group-lifecycle-crud."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-group-lifecycle-crud"
GROUP = "control-plane"
SERVICES = ["dax"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateParameterGroup changes a parameter's value (Source stays "user"), and after DeleteParameterGroup
    DescribeParameterGroups fails with ParameterGroupNotFoundFault "Parameter Group not found." and
    UpdateParameterGroup with "ParameterGroup not found: <name>"."""
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-pg-")
    dax.create_parameter_group(ParameterGroupName=name, Description="sim2real test group")
    ctx.on_cleanup(lambda: _safe_delete_parameter_group(ctx, name))

    described = dax.describe_parameter_groups(ParameterGroupNames=[name])["ParameterGroups"][0]
    assert described["ParameterGroupName"] == name, (
        f"expected DescribeParameterGroups to echo back {name!r}, got {described['ParameterGroupName']!r}"
    )
    assert described["Description"] == "sim2real test group", (
        f"expected the create-time description to round-trip, got {described['Description']!r}"
    )

    params_before = _list_parameters(ctx, name)
    assert params_before, "expected a freshly created parameter group to inherit default parameters"
    param_name, new_value, original_source, original_value = _pick_immediate_integer_param(params_before)
    assert new_value != original_value, (
        f"picked candidate value {new_value!r} for {param_name!r} must differ from its current value {original_value!r}"
    )
    assert original_source == "user", (
        f"expected a freshly created, never-modified {param_name!r} to already report Source 'user' "
        f"(DAX does not distinguish engine-default from customer-set via Source), got {original_source!r}"
    )

    dax.update_parameter_group(
        ParameterGroupName=name,
        ParameterNameValues=[{"ParameterName": param_name, "ParameterValue": str(new_value)}],
    )

    params_after = _list_parameters(ctx, name)
    updated = next(p for p in params_after if p["ParameterName"] == param_name)
    assert updated["ParameterValue"] == str(new_value), (
        f"expected {param_name!r} to read back as {new_value!r} after UpdateParameterGroup, got {updated['ParameterValue']!r}"
    )
    assert updated["Source"] == "user", (
        f"expected {param_name!r}'s Source to still read back as 'user' after UpdateParameterGroup "
        f"(Source does not flip on customization on real AWS), got {updated['Source']!r}"
    )

    dax.delete_parameter_group(ParameterGroupName=name)
    code, message = _expect_error(lambda: dax.describe_parameter_groups(ParameterGroupNames=[name]))
    assert code == "ParameterGroupNotFoundFault", (
        f"expected DescribeParameterGroups on the deleted group {name!r} to fail with "
        f"ParameterGroupNotFoundFault, got {code!r}"
    )
    assert message == "Parameter Group not found.", f"unexpected message: {message!r}"

    update_after_delete_code, update_after_delete_message = _expect_error(
        lambda: dax.update_parameter_group(
            ParameterGroupName=name,
            ParameterNameValues=[{"ParameterName": param_name, "ParameterValue": str(original_value)}],
        )
    )
    assert update_after_delete_code == "ParameterGroupNotFoundFault", (
        f"expected UpdateParameterGroup on the deleted group {name!r} to also fail with "
        f"ParameterGroupNotFoundFault, got {update_after_delete_code!r}"
    )
    assert update_after_delete_message == f"ParameterGroup not found: {name}", (
        f"unexpected message: {update_after_delete_message!r}"
    )


def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_parameter_group(ctx, name):
    try:
        ctx.client("dax").delete_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ParameterGroupNotFoundFault",
            "ServiceLinkedRoleNotFoundFault",
        ):
            raise


def _list_parameters(ctx, parameter_group_name):
    dax = ctx.client("dax")
    out = []
    token = None
    while True:
        kwargs = {"ParameterGroupName": parameter_group_name}
        if token:
            kwargs["NextToken"] = token
        resp = dax.describe_parameters(**kwargs)
        out.extend(resp["Parameters"])
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _pick_immediate_integer_param(parameters):
    """Pick a customer-modifiable, IMMEDIATE-apply, numeric-range parameter and a
    valid new value distinct from its current default -- discovered dynamically so
    the check does not depend on a hardcoded DAX parameter name.

    AllowedValues for a numeric-range parameter is "lo-hi", but DAX's own
    query-ttl-millis/record-ttl-millis report an open-ended "lo-" with no upper
    bound (confirmed against real AWS) -- an empty hi means unbounded, not invalid."""
    for p in parameters:
        if p.get("IsModifiable") != "TRUE" or p.get("ChangeType") != "IMMEDIATE":
            continue
        allowed = p.get("AllowedValues") or ""
        if "-" not in allowed:
            continue
        lo_s, _, hi_s = allowed.partition("-")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else None
            current = int(p["ParameterValue"])
        except ValueError:
            continue
        if hi is not None:
            candidate = current + 1 if current + 1 <= hi else max(lo, current - 1)
        else:
            candidate = current + 1 if current + 1 >= lo else lo
        if candidate == current:
            continue
        return p["ParameterName"], candidate, p.get("Source"), p["ParameterValue"]
    raise AssertionError(
        "no customer-modifiable IMMEDIATE-apply numeric-range DAX parameter found via "
        "DescribeDefaultParameters to exercise UpdateParameterGroup"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
