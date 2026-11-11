"""register-application-invalid-instance-pattern-rejected."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "register-application-invalid-instance-pattern-rejected"
GROUP = "validation"
SERVICES = ["ssm-sap"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Instances entry that does not match the EC2 instance ID pattern is rejected with
    ValidationException, while a pattern-valid (if nonexistent) instance id in the same call
    shape is accepted synchronously."""
    role_freshly_created = _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    bad_id = ctx.unique_name("sim2real-sap-bad-").replace("_", "-")[:60]

    err = _error(
        lambda: client.register_application(
            ApplicationId=bad_id,
            ApplicationType="HANA",
            Instances=["not-an-ec2-instance-id"],
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected = (
        "1 validation error detected: Value '[not-an-ec2-instance-id]' at 'instances' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must satisfy regular "
        "expression pattern: i-[\\w\\d]{8}$|^i-[\\w\\d]{17}]"
    )
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    # effect absent: no application was created by the rejected call
    missing = _error(lambda: client.get_application(ApplicationId=bad_id))
    assert missing["Code"] == "ValidationException", f"expected {bad_id} to be absent, got {missing!r}"
    expected_missing = f"No registered application found for account: {ctx.account}, and application: {bad_id}"
    assert missing.get("Message") == expected_missing, (
        f"expected message {expected_missing!r}, got {missing.get('Message')!r}"
    )

    # positive control: a pattern-valid instance id is accepted
    good_id = ctx.unique_name("sim2real-sap-good-").replace("_", "-")[:60]
    good_instance = "i-" + secrets.token_hex(9)[:17]
    resp = _register_application_with_retry(
        client,
        role_freshly_created,
        ApplicationId=good_id,
        ApplicationType="HANA",
        Instances=[good_instance],
        Sid="HDB",
        SapInstanceNumber="00",
        Tags={"sim2real": CHECK},
        Credentials=[
            {
                "CredentialType": "ADMIN",
                "DatabaseName": "HDB/HDB",
                "SecretId": "sim2real-fake-secret-id",
            }
        ],
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, good_id))
    assert resp["Application"]["Id"] == good_id, f"expected {good_id}, got {resp['Application'].get('Id')!r}"

    # terminal read: independent of the RegisterApplication call that created it
    created = client.get_application(ApplicationId=good_id)["Application"]
    assert created["Id"] == good_id, f"expected {good_id} visible via GetApplication, got {created.get('Id')!r}"
    assert created["Type"] == "HANA", f"expected Type HANA, got {created.get('Type')!r}"


def _ensure_service_linked_role(ctx) -> bool:
    """Ensures AWSServiceRoleForAWSSSMForSAP exists. Returns True only when
    this call just created it, so the caller knows the role may still be
    propagating IAM-side and can bound a retry around the dependent call
    instead of sleeping blind."""
    import time

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
        return False
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
            return True
        except ClientError:
            time.sleep(5.0)
    raise TimeoutError("AWSServiceRoleForAWSSSMForSAP did not become visible within 60s of creation")


def _register_application_with_retry(client, retry_for_role_propagation: bool, **kwargs):
    """RegisterApplication can fail while the just-created service-linked
    role is still propagating IAM-side; retry only in the run that just
    created the role, bounded, re-raising the real error on timeout."""
    import time

    from botocore.exceptions import ClientError

    if not retry_for_role_propagation:
        return client.register_application(**kwargs)
    deadline = time.monotonic() + 30.0
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
