"""delete-default-parameter-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-default-parameter-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["dax"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteParameterGroup on the account's default DAX parameter group fails with InvalidParameterValueException
    and its exact message and the group remains, while a created group deletes and then describes as
    ParameterGroupNotFoundFault "Parameter Group not found."."""
    dax = ctx.client("dax")
    default_name = _find_default_parameter_group(ctx)

    code, message = _expect_error(lambda: dax.delete_parameter_group(ParameterGroupName=default_name))
    assert code == "InvalidParameterValueException", f"unexpected code: {code!r}"
    assert message == (
        "The parameter CacheParameterGroupName is not a valid identifier. Identifiers must begin "
        "with a letter; must contain only ASCII letters, digits, and hyphens; and must not end "
        "with a hyphen or contain two consecutive hyphens."
    ), f"unexpected message: {message!r}"

    still_there = dax.describe_parameter_groups(ParameterGroupNames=[default_name])["ParameterGroups"][0]
    assert still_there["ParameterGroupName"] == default_name, (
        f"expected {default_name!r} to remain after the rejected delete, "
        f"got {still_there['ParameterGroupName']!r}"
    )

    custom_name = ctx.unique_name("sim2real-dax-pg-")
    dax.create_parameter_group(ParameterGroupName=custom_name, Description="control")
    ctx.on_cleanup(lambda: _safe_delete_parameter_group(ctx, custom_name))
    dax.delete_parameter_group(ParameterGroupName=custom_name)
    gone_code, gone_message = _expect_error(
        lambda: dax.describe_parameter_groups(ParameterGroupNames=[custom_name])
    )
    assert gone_code == "ParameterGroupNotFoundFault", (
        f"expected the deleted control group {custom_name!r} to read back "
        f"ParameterGroupNotFoundFault, got {gone_code!r}"
    )
    assert gone_message == "Parameter Group not found.", f"unexpected message: {gone_message!r}"


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


def _find_default_parameter_group(ctx):
    dax = ctx.client("dax")
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = dax.describe_parameter_groups(**kwargs)
        for pg in resp["ParameterGroups"]:
            if pg["ParameterGroupName"].startswith("default."):
                return pg["ParameterGroupName"]
        token = resp.get("NextToken")
        if not token:
            break
    raise AssertionError("no system default DAX parameter group (name prefix 'default.') found in this account/region")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
