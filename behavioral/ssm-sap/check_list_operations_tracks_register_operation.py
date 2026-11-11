"""list-operations-tracks-register-operation."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "list-operations-tracks-register-operation"
GROUP = "operations"
SERVICES = ["ssm-sap"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOperations for an application surfaces the exact Operation created
    by RegisterApplication, with matching Id/ResourceId/ResourceArn, and
    ListOperationEvents accepts that same OperationId without error."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]

    resp = _register_application_with_retry(client, app_id, instance_id)
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, app_id))
    operation_id = resp["OperationId"]
    app_arn = resp["Application"]["Arn"]

    operations = client.list_operations(ApplicationId=app_id)["Operations"]
    matches = [o for o in operations if o["Id"] == operation_id]
    assert len(matches) == 1, (
        f"expected exactly one operation with Id {operation_id!r}, "
        f"found {len(matches)} among {[o['Id'] for o in operations]}"
    )
    tracked = matches[0]
    assert tracked["ResourceId"] == app_id, (
        f"expected tracked operation ResourceId {app_id!r}, got {tracked['ResourceId']!r}"
    )
    # ResourceArn on the Operation is documented as optional; only assert
    # agreement when the field is actually populated.
    if tracked.get("ResourceArn"):
        assert tracked["ResourceArn"] == app_arn, (
            f"expected tracked operation ResourceArn {app_arn!r}, got {tracked['ResourceArn']!r}"
        )

    # ListOperationEvents accepts the id without error (events may or may
    # not have landed yet -- that timing is not guaranteed).
    events_resp = client.list_operation_events(OperationId=operation_id)
    assert "OperationEvents" in events_resp, (
        f"expected ListOperationEvents({operation_id!r}) to return an "
        f"OperationEvents field, got keys {sorted(events_resp)}"
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
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
            break
        except ClientError:
            time.sleep(5.0)


def _register_application_with_retry(client, app_id: str, instance_id: str) -> dict:
    """A freshly created AWSServiceRoleForAWSSSMForSAP is visible in IAM
    before ssm-sap's control plane can use it, so RegisterApplication can
    reject with a transient error for a few seconds after
    _ensure_service_linked_role returns. Retry the call itself against a
    deadline instead of guessing how long propagation takes with a sleep."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            return client.register_application(
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
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


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

    deadline = time.monotonic() + 300.0
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
            raise AssertionError(f"application {app_id} was not deregistered within 300s of teardown")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
