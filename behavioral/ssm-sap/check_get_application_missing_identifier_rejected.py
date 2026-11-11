"""get-application-missing-identifier-rejected."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "get-application-missing-identifier-rejected"
GROUP = "validation"
SERVICES = ["ssm-sap"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApplication with none of ApplicationId/ApplicationArn/AppRegistryArn
    supplied is rejected with ValidationException, while supplying a real
    ApplicationId succeeds."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")

    err = _error(lambda: client.get_application())
    assert err["Code"] == "ValidationException", err
    expected = "applicationId or applicationArn need to be specified"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # positive control: a real ApplicationId succeeds
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]
    _register_application_with_retry(
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
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, app_id))
    got = client.get_application(ApplicationId=app_id)["Application"]["Id"]
    assert got == app_id, f"expected GetApplication to echo {app_id!r}, got {got!r}"


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
            return
        except ClientError:
            time.sleep(5.0)
    raise TimeoutError(
        "AWSServiceRoleForAWSSSMForSAP did not become visible within 60s of creation"
    )


def _register_application_with_retry(client, **kwargs):
    """RegisterApplication can fail while a just-created AWSServiceRoleForAWSSSMForSAP's
    trust policy is still propagating; retry the actual dependent call on a bounded
    deadline instead of guessing a fixed propagation delay."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            return client.register_application(**kwargs)
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
