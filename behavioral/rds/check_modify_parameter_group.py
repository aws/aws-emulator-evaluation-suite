"""modify-parameter-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-parameter-group"
GROUP = 'parameter_groups'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBParameterGroup sets a parameter; DescribeDBParameters(Source='user') reflects the
    value and ApplyMethod. After the group is deleted, an independent read returns the specific
    not-found code and a further modify on the dead id is refused with the same code."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rds.delete_db_parameter_group(DBParameterGroupName=name), "DBParameterGroupNotFound"))
    rds.modify_db_parameter_group(
        DBParameterGroupName=name,
        Parameters=[
            {
                "ParameterName": "max_connections",
                "ParameterValue": "200",
                "ApplyMethod": "pending-reboot",
            }
        ],
    )
    stored = {
        p["ParameterName"]: p
        for page in rds.get_paginator("describe_db_parameters").paginate(
            DBParameterGroupName=name, Source="user"
        )
        for p in page.get("Parameters", [])
    }
    assert stored.get("max_connections", {}).get("ParameterValue") == "200", (
        f"Source='user' must list the modified max_connections value as '200'; got "
        f"{stored.get('max_connections')!r}"
    )
    assert stored["max_connections"].get("ApplyMethod") == "pending-reboot", (
        f"ApplyMethod must round-trip as 'pending-reboot'; got "
        f"{stored['max_connections'].get('ApplyMethod')!r}"
    )

    rds.delete_db_parameter_group(DBParameterGroupName=name)
    code = message = None
    try:
        rds.describe_db_parameter_groups(DBParameterGroupName=name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_PARAMETER_GROUP_NOT_FOUND} after delete, got {code!r}"
    )
    assert message == f"DBParameterGroup not found: {name}", message

    code2 = message2 = None
    try:
        rds.modify_db_parameter_group(
            DBParameterGroupName=name,
            Parameters=[
                {
                    "ParameterName": "max_connections",
                    "ParameterValue": "210",
                    "ApplyMethod": "pending-reboot",
                }
            ],
        )
    except ClientError as exc:
        code2 = exc.response.get("Error", {}).get("Code")
        message2 = exc.response.get("Error", {}).get("Message")
    assert code2 == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"a modify on the deleted group must also fail with "
        f"{ERR_DB_PARAMETER_GROUP_NOT_FOUND}; got {code2!r}"
    )
    assert message2 == f"DBParameterGroup not found: {name}", message2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
