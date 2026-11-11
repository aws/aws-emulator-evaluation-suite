"""register-application-discovery-status-transition."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "register-application-discovery-status-transition"
GROUP = "lifecycle"
SERVICES = ["ssm-sap"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An application registered against an instance with no SSM Agent or SAP software ends FAILED
    with DiscoveryStatus REGISTRATION_FAILED once async discovery completes, and its tracked
    Operation converges to ERROR."""
    client = ctx.client("ssm-sap")
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]

    resp = client.register_application(
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
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, app_id))
    operation_id = resp["OperationId"]
    assert resp["Application"]["Status"] == "REGISTERING", resp["Application"]

    deadline = time.monotonic() + 300.0
    final_app = None
    while time.monotonic() < deadline:
        app = client.get_application(ApplicationId=app_id)["Application"]
        if app["Status"] != "REGISTERING":
            final_app = app
            break
        time.sleep(2)

    assert final_app is not None, (
        "Application.Status never left REGISTERING within 300s"
    )
    assert final_app["Status"] == "FAILED", final_app
    assert final_app["DiscoveryStatus"] == "REGISTRATION_FAILED", final_app

    operation = client.get_operation(OperationId=operation_id)["Operation"]
    assert operation["Status"] == "ERROR", operation


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
    # IAM read-after-write consistency means get_role can report the role before
    # ssm-sap's own control plane sees it; require 3 consecutive confirmed reads,
    # 5s apart, bounded at 60s, instead of a blind settle sleep.
    deadline = time.monotonic() + 60.0
    consecutive = 0
    while time.monotonic() < deadline and consecutive < 3:
        try:
            iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
            consecutive += 1
        except ClientError:
            consecutive = 0
        time.sleep(5.0)
    assert consecutive >= 3, "AWSServiceRoleForAWSSSMForSAP never stabilized within 60s"


def _purge_stale_apps(ctx) -> None:
    from botocore.exceptions import ClientError

    client = ctx.client("ssm-sap")
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        try:
            page = client.list_applications(MaxResults=50, **kwargs)
        except ClientError:
            return
        for a in page.get("Applications", []):
            if a.get("Id", "").startswith("sim2real-sap-") and a.get("Status") != "REGISTERING":
                try:
                    client.deregister_application(ApplicationId=a["Id"])
                except ClientError:
                    pass
        token = page.get("NextToken")
        if not token:
            break


def _deregister_ignore_errors(ctx, app_id: str) -> None:
    """Teardown: deregister once the application leaves REGISTERING, retrying ConflictException;
    returns once the deregister is accepted or the application is gone, and raises any other error."""
    import time

    from botocore.exceptions import ClientError

    client = ctx.client("ssm-sap")

    def _gone(exc) -> bool:
        err = exc.response["Error"]
        return err["Code"] == "ValidationException" and err.get("Message", "").startswith(
            "No registered application found"
        )

    deadline = time.monotonic() + 240.0
    while True:
        try:
            status = client.get_application(ApplicationId=app_id)["Application"].get("Status")
        except ClientError as exc:
            if _gone(exc):
                return
            raise
        if status != "REGISTERING":
            try:
                client.deregister_application(ApplicationId=app_id)
                return
            except ClientError as exc:
                if _gone(exc):
                    return
                if exc.response["Error"]["Code"] != "ConflictException":
                    raise
        if time.monotonic() > deadline:
            raise AssertionError(f"application {app_id} was not deregistered within 240s of teardown")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
