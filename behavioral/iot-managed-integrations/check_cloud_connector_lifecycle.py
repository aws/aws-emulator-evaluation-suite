"""cloud-connector-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloud-connector-lifecycle"
GROUP = "crud-depth"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cloud connector round-trips its name, Lambda endpoint ARN and updated
    description; after delete, Get and Update on it fail with ResourceNotFoundException
    and their exact messages."""
    iot = _iot_client(ctx)
    lam = _lambda_client(ctx)
    name = ctx.unique_name("sim2real-connector-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fn_name = _deploy_function(ctx, lam, account_id)
    lambda_arn = lam.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]

    created = iot.create_cloud_connector(
        Name=name, EndpointConfig={"lambda": {"arn": lambda_arn}}
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_connector_ignore_missing(iot, connector_id))

    got = iot.get_cloud_connector(Identifier=connector_id)
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["EndpointConfig"]["lambda"]["arn"] == lambda_arn, (
        f"expected lambda arn {lambda_arn!r}, got {got['EndpointConfig']['lambda']['arn']!r}"
    )

    iot.update_cloud_connector(Identifier=connector_id, Description="updated description")
    updated = iot.get_cloud_connector(Identifier=connector_id)
    assert updated["Description"] == "updated description", (
        f"expected updated Description, got {updated['Description']!r}"
    )
    assert updated["Name"] == name, f"Name changed by an update that only touched Description: {updated['Name']!r}"

    iot.delete_cloud_connector(Identifier=connector_id)
    code, message = _error(lambda: iot.get_cloud_connector(Identifier=connector_id))
    assert code == "ResourceNotFoundException", f"get after delete: expected ResourceNotFoundException, got {code}"
    expected = "Cloud connector not found."
    assert message == expected, f"get after delete: expected message {expected!r}, got {message!r}"

    mutate_code, mutate_message = _error(
        lambda: iot.update_cloud_connector(Identifier=connector_id, Description="post-delete")
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"update on deleted connector: expected ResourceNotFoundException, got {mutate_code}"
    )
    expected = "Cloud connector not found."
    assert mutate_message == expected, (
        f"update on deleted connector: expected message {expected!r}, got {mutate_message!r}"
    )


def _iot_client(ctx):
    # iot-managed-integrations is offered in ca-central-1 and eu-west-1 only, so this client
    # pins the region; ctx.client keeps the run's credentials and endpoint routing.
    return ctx.client("iot-managed-integrations", region="eu-west-1")


def _lambda_client(ctx):
    # The connector's Lambda endpoint is validated by a live lookup at CreateCloudConnector
    # time (see run()'s docstring), so the function must exist where the connector call
    # lands: eu-west-1 on real AWS, same as _iot_client.
    return ctx.client("lambda", region="eu-west-1")


def _create_role(ctx) -> str:
    """The function's execution role, created by this check and deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    return role_arn


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _wait_active(lam, fn_name: str, timeout_s: float = 60) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn_name)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn_name} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn_name} did not reach Active within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, account_id: str) -> str:
    fn_name = ctx.unique_name("sim2real-cc-fn-")
    role_arn = _create_role(ctx)
    # A new role takes a few seconds to become assumable by Lambda; retry only that refusal.
    deadline = time.monotonic() + 60
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Handler="index.handler",
                Role=role_arn,
                Code={"ZipFile": _make_zip("def handler(e, c): return e")},
                MemorySize=128,
                Timeout=10,
            )
            break
        except ClientError as e:
            assumable_later = (
                e.response["Error"]["Code"] == "InvalidParameterValueException"
                and "cannot be assumed" in e.response["Error"].get("Message", "")
            )
            if not assumable_later or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, fn_name))
    _wait_active(lam, fn_name)
    # The cloud connector's live existence check is made by the iotmanagedintegrations
    # service, not by this caller, so the function needs a resource policy granting that
    # service principal permission to look it up — the same idiom any AWS service that
    # invokes a customer's Lambda on their behalf uses.
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-allow-iotmanagedintegrations",
        Action="lambda:InvokeFunction",
        Principal="iotmanagedintegrations.amazonaws.com",
        SourceAccount=account_id,
    )
    return fn_name


def _cleanup_function(ctx, lam, fn_name: str) -> None:
    try:
        lam.delete_function(FunctionName=fn_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs = ctx.client("logs", region="eu-west-1")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _delete_connector_ignore_missing(iot, connector_id: str) -> None:
    try:
        iot.delete_cloud_connector(Identifier=connector_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
