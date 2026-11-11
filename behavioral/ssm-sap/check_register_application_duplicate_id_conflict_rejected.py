"""register-application-duplicate-id-conflict-rejected."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "register-application-duplicate-id-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-sap"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Registering a second application under an ApplicationId that already
    exists is rejected with ConflictException, and the original application's
    identity (Arn/Type) is left untouched by the rejected attempt."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]

    first = _register_application_with_retry(
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
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, app_id))
    original_arn = first["Application"]["Arn"]

    other_instance_id = "i-" + secrets.token_hex(9)[:17]
    err = _error(
        lambda: client.register_application(
            ApplicationId=app_id,
            ApplicationType="HANA",
            Instances=[other_instance_id],
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
    )
    assert err["Code"] == "ConflictException", (
        f"expected ConflictException for a duplicate ApplicationId, got {err!r}"
    )
    expected = f"Application id '{app_id}' already exists."
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # positive control: the original registration is unaffected by the
    # rejected duplicate attempt
    current = client.get_application(ApplicationId=app_id)["Application"]
    assert current["Arn"] == original_arn, (
        f"original application Arn changed after a rejected duplicate "
        f"registration: expected {original_arn!r}, got {current['Arn']!r}"
    )
    assert current["Id"] == app_id, f"expected Id {app_id!r}, got {current['Id']!r}"


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


def _register_application_with_retry(client, timeout_s=30.0, **kwargs):
    """IAM reporting the service-linked role as visible does not mean ssm-sap
    can use it yet; retry the (idempotent, side-effect-free-on-failure) first
    registration until it is accepted instead of guessing a fixed propagation
    delay."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.register_application(**kwargs)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


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


def _error(fn):
    """Call fn(); return its botocore error dict (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails here rather than as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
