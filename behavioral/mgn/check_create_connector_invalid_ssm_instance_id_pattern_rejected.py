"""create-connector-invalid-ssm-instance-id-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connector-invalid-ssm-instance-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnector refuses a malformed ssmInstanceID with BadRequestException ahead of the
    initialization gate, while a well-formed nonexistent id gets UninitializedAccountException,
    and ListConnectors is refused by the same gate.
    """
    mgn = ctx.client("mgn")
    bad_name = ctx.unique_name("sim2real-mgn-connector-bad-")
    good_name = ctx.unique_name("sim2real-mgn-connector-ok-")

    bad_code, bad_message = None, None
    bad_id = None
    try:
        resp = mgn.create_connector(name=bad_name, ssmInstanceID="not-a-valid-ssm-instance-id")
        bad_id = resp.get("connectorID")
    except ClientError as exc:
        bad_code = exc.response.get("Error", {}).get("Code")
        bad_message = exc.response.get("Error", {}).get("Message")
    if bad_id:
        ctx.on_cleanup(lambda: mgn.delete_connector(connectorID=bad_id))
    assert bad_id is None, (
        f"CreateConnector with a malformed ssmInstanceID must not create a connector, "
        f"got connectorID={bad_id!r}"
    )
    assert bad_code == "BadRequestException", (
        f"CreateConnector with a malformed ssmInstanceID must raise BadRequestException, "
        f"got {bad_code!r}"
    )
    assert bad_message == "Invalid request body", (
        f"CreateConnector with a malformed ssmInstanceID must answer 'Invalid request body', "
        f"got {bad_message!r}"
    )

    good_code, good_message = None, None
    good_id = None
    try:
        resp = mgn.create_connector(
            name=good_name,
            ssmInstanceID="mi-" + "0" * 17,
            tags={"sim2real-key": "sim2real-value"},
        )
        good_id = resp.get("connectorID")
    except ClientError as exc:
        good_code = exc.response.get("Error", {}).get("Code")
        good_message = exc.response.get("Error", {}).get("Message")
    if good_id:
        ctx.on_cleanup(lambda: mgn.delete_connector(connectorID=good_id))
    assert good_code == "UninitializedAccountException", (
        f"a well-formed but nonexistent ssmInstanceID must clear field validation and "
        f"fail one step later on the account-initialization gate, got {good_code!r} "
        f"(connectorID={good_id!r})"
    )
    assert good_message == "Account not initialized", (
        f"the account-initialization refusal must answer 'Account not initialized', got {good_message!r}"
    )
    assert bad_code != good_code, (
        "a malformed ssmInstanceID and a well-formed one must fail for different reasons -- "
        "otherwise CreateConnector is rejecting every call for the same account-level reason "
        "and the pattern boundary is not being exercised at all"
    )

    list_code, list_message = None, None
    try:
        mgn.list_connectors()
    except ClientError as exc:
        list_code = exc.response.get("Error", {}).get("Code")
        list_message = exc.response.get("Error", {}).get("Message")
    assert list_code == "UninitializedAccountException", (
        f"the independent read at the destination, ListConnectors, must also honor the "
        f"account-initialization gate on this uninitialized account, got {list_code!r} -- "
        f"so no connector, malformed or otherwise, is ever reachable through it"
    )
    assert list_message == "Account not initialized", (
        f"the account-initialization refusal must answer 'Account not initialized', got {list_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
