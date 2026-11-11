"""register-application-synchronous-response-state."""
from __future__ import annotations

import re
import secrets

from behavioral_harness import tags

CHECK = "register-application-synchronous-response-state"
GROUP = "lifecycle"
SERVICES = ["ssm-sap"]


# The relayed message ends with the inner call's request id and the SDK attempt count; those
# are the only parts that vary per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"SDK Attempt Count: [0-9]+")


def _stable(message):
    if message is None:
        return None
    return _ATTEMPTS.sub("SDK Attempt Count: <n>", _REQUEST_ID.sub("Request ID: <request-id>", message))

_UUID_RE = re.compile(r"^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterApplication returns Status=REGISTERING and an Operation that GetOperation (INPROGRESS
    or ERROR) and ListOperations find linked to the application; for a nonexistent instance it
    ends ERROR with the relayed SendCommand denial, and the application ends FAILED."""
    _ensure_service_linked_role(ctx)
    client = ctx.client("ssm-sap")
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = _fake_instance_id()

    resp = _register_application_awaiting_role_propagation(
        client,
        ApplicationId=app_id,
        ApplicationType="HANA",
        Instances=[instance_id],
        Sid="HDB",
        SapInstanceNumber="00",
        Credentials=[
            {
                "CredentialType": "ADMIN",
                "DatabaseName": "HDB/HDB",
                "SecretId": "sim2real-fake-secret-id",
            }
        ],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, app_id))

    app = resp["Application"]
    assert app["Id"] == app_id, f"expected Id {app_id!r}, got {app['Id']!r}"
    assert app["Type"] == "HANA", f"expected Type HANA, got {app['Type']!r}"
    assert app["Status"] == "REGISTERING", f"expected Status REGISTERING, got {app['Status']!r}"
    assert app["DiscoveryStatus"] == "REGISTERING", (
        f"expected DiscoveryStatus REGISTERING, got {app['DiscoveryStatus']!r}"
    )

    operation_id = resp["OperationId"]
    assert _UUID_RE.match(operation_id), f"OperationId {operation_id!r} is not a UUID"

    operation = client.get_operation(OperationId=operation_id)["Operation"]
    assert operation["Id"] == operation_id, (
        f"GetOperation returned Id {operation['Id']!r}, expected {operation_id!r}"
    )
    assert operation["ResourceId"] == app_id, (
        f"Operation.ResourceId {operation['ResourceId']!r} does not link back to {app_id!r}"
    )
    # The operation fails fast and no INPROGRESS duration is documented, so the first read may
    # already be the terminal ERROR.
    assert operation["Status"] in ("INPROGRESS", "ERROR"), (
        f"expected the just-created Operation to be INPROGRESS or ERROR, got {operation['Status']!r}"
    )

    ops_page = client.list_operations(ApplicationId=app_id)["Operations"]
    assert operation_id in {o["Id"] for o in ops_page}, (
        "ListOperations for the application did not include the operation "
        "returned by RegisterApplication"
    )

    terminal = _poll_operation_terminal(client, operation_id)
    assert terminal["Status"] == "ERROR", (
        f"expected the registration Operation to end in ERROR, got {terminal['Status']!r}"
    )
    # StatusMessage relays the SendCommand refusal; its request id and attempt count are the only
    # varying parts.
    expected_status_message = (
        "Error executing SSM document - AccessDeniedException User: "
        f"arn:aws:sts::{ctx.account}:assumed-role/AWSServiceRoleForAWSSSMForSAP/ssm-sap is not "
        f"authorized to perform: ssm:SendCommand on resource: arn:aws:ec2:{ctx.region}:{ctx.account}:"
        f"instance/{instance_id} because no identity-based policy allows the ssm:SendCommand action "
        "(Service: Ssm, Status Code: 400, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert _stable(terminal.get("StatusMessage")) == expected_status_message, (
        f"expected StatusMessage {expected_status_message!r}, got {terminal.get('StatusMessage')!r}"
    )
    final = client.get_application(ApplicationId=app_id)["Application"]
    assert final["Status"] == "FAILED", f"expected application Status FAILED, got {final['Status']!r}"
    assert final["DiscoveryStatus"] == "REGISTRATION_FAILED", (
        f"expected DiscoveryStatus REGISTRATION_FAILED, got {final['DiscoveryStatus']!r}"
    )


def _ensure_service_linked_role(ctx) -> None:
    import time

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.create_service_linked_role(AWSServiceName="ssm-sap.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise
    deadline = time.monotonic() + 60.0
    while True:
        try:
            iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "AWSServiceRoleForAWSSSMForSAP did not become visible within 60s "
                    "of create_service_linked_role"
                )
            time.sleep(5.0)


def _register_application_awaiting_role_propagation(client, **kwargs):
    """RegisterApplication rejects with a specific ValidationException while the
    just-created AWSServiceRoleForAWSSSMForSAP is still propagating to ssm-sap's
    control plane -- the service's own error message says to retry after "a few
    minutes". Retry only that exact, named condition; anything else raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    while True:
        try:
            return client.register_application(**kwargs)
        except ClientError as e:
            message = e.response["Error"].get("Message", "")
            if (
                e.response["Error"]["Code"] == "ValidationException"
                and "AWSServiceRoleForAWSSSMForSAP" in message
                and "propagate" in message
                and time.monotonic() < deadline
            ):
                time.sleep(2)
                continue
            raise


def _poll_operation_terminal(client, operation_id: str, timeout_s: float = 600.0) -> dict:
    """GetOperation until the Operation leaves INPROGRESS; raises on timeout."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        operation = client.get_operation(OperationId=operation_id)["Operation"]
        if operation["Status"] != "INPROGRESS":
            return operation
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"operation {operation_id} still INPROGRESS after {timeout_s}s: {operation!r}"
            )
        time.sleep(2)


def _fake_instance_id() -> str:
    return "i-" + secrets.token_hex(9)[:17]


def _deregister_ignore_errors(ctx, app_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("ssm-sap").deregister_application(ApplicationId=app_id)
    except ClientError as exc:
        err = exc.response["Error"]
        # A missing application is a ValidationException "No registered application found ...".
        if not (err["Code"] == "ValidationException"
                and err.get("Message", "").startswith("No registered application found")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
