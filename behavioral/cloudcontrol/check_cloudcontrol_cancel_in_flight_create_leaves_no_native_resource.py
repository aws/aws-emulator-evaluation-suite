"""cloudcontrol-cancel-in-flight-create-leaves-no-native-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-cancel-in-flight-create-leaves-no-native-resource"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
DDB_TABLE_TYPE = "AWS::DynamoDB::Table"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _poll_until(probe, predicate, *, timeout_s=240, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error_code(fn):
    """The AWS error code and message raised by fn(). Raises if the call unexpectedly SUCCEEDS -- returning a
    falsy sentinel there would turn the strongest possible signal into a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    prefix = f"{detail} (HandlerErrorCode: NotFound, RequestToken: "
    return message.startswith(prefix) and message.endswith(")")


def _drop_table_quiet(ddb, name):
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _desired_state(name):
    """A DynamoDB table takes tens of seconds to stabilize, which is what makes the in-flight
    window wide enough to cancel without a race. A KMS-encrypted log group would also lengthen the
    handler run, but a CMK cannot be deleted for 7 days and would outlive the check."""
    return json.dumps({
        "TableName": name,
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    })


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Cancelling an in-flight CreateResource of a DynamoDB table reaches CANCEL_COMPLETE and leaves no
    table in DynamoDB, while an uncancelled create in the same run proves Cloud Control reaches
    DynamoDB at all.
    """
    cc = ctx.client("cloudcontrol")
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-cccancel-")

    started = cc.create_resource(TypeName=DDB_TABLE_TYPE, DesiredState=_desired_state(name))
    token = started["ProgressEvent"]["RequestToken"]
    # Registered before the first assertion: a cancel that lost the race leaves a real table, and
    # the only reapable handle is the DynamoDB table name, not the Cloud Control request token.
    ctx.on_cleanup(lambda: _drop_table_quiet(ddb, name))

    # The cancel goes out at once, inside the table's tens-of-seconds stabilization; CANCEL_COMPLETE
    # below proves it reached the create in flight.
    cc.cancel_resource_request(RequestToken=token)
    final = _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        description=f"request {token} reaching a terminal OperationStatus after the cancel",
    )
    assert final["OperationStatus"] == "CANCEL_COMPLETE", (
        f"the cancelled create ended {final['OperationStatus']!r}: a cancel that is accepted but "
        f"has no effect on the state machine is the failure mode here -- {final!r}"
    )
    assert final["RequestToken"] == token, f"the terminal event is for another request: {final!r}"

    listed = []
    for page in ddb.get_paginator("list_tables").paginate():
        listed.extend(page["TableNames"])
    assert name not in listed, (
        f"the cancelled create left an orphan table in DynamoDB; ListTables holds {len(listed)!r} "
        f"tables including {name!r}"
    )
    describe_code, describe_message = _error_code(lambda: ddb.describe_table(TableName=name))
    assert describe_code == "ResourceNotFoundException", (
        f"DynamoDB DescribeTable answered {describe_code!r} for a table whose create was cancelled"
    )
    assert describe_message == f"Requested resource not found: Table: {name} not found", describe_message
    cc_code, cc_message = _error_code(lambda: cc.get_resource(TypeName=DDB_TABLE_TYPE, Identifier=name))
    assert cc_code == "ResourceNotFoundException", f"GetResource after the cancel raised {cc_code!r}"
    assert _handler_not_found(
        cc_message, f"{DDB_TABLE_TYPE} Handler returned status FAILED: Table: {name} does not exist."
    ), cc_message

    # Positive control, same wiring, same run: an uncancelled create on the same TypeName really
    # does produce a native table, so the absence proven above is not "this account's CloudControl
    # never reaches DynamoDB at all".
    control_name = ctx.unique_name("sim2real-behav-cccancel-ctrl-")
    ctx.on_cleanup(lambda: _drop_table_quiet(ddb, control_name))
    control_started = cc.create_resource(TypeName=DDB_TABLE_TYPE, DesiredState=_desired_state(control_name))
    control_token = control_started["ProgressEvent"]["RequestToken"]
    control_final = _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=control_token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=200,
        description=f"uncancelled control create {control_name} reaching a terminal OperationStatus",
    )
    assert control_final["OperationStatus"] == "SUCCESS", (
        f"the positive control -- an uncancelled create on the same wiring -- did not reach SUCCESS, "
        f"so the absence proven above cannot be trusted as a real cancel effect: {control_final!r}"
    )
    control_status = ddb.describe_table(TableName=control_name)["Table"]["TableStatus"]
    assert control_status in ("ACTIVE", "CREATING", "UPDATING"), (
        f"the uncancelled control table is not visible via native DescribeTable: {control_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
