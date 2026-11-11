"""register-application-sap-abap-credentials-rejected."""
from __future__ import annotations

import secrets

from behavioral_harness import tags

CHECK = "register-application-sap-abap-credentials-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-sap"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Credentials apply only to HANA registrations: supplying them for a SAP_ABAP application is
    rejected with ValidationException, while the same call without Credentials (or a HANA
    registration with Credentials) succeeds."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    abap_id = ctx.unique_name("sim2real-sap-abap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]
    credentials = [
        {
            "DatabaseName": "HDB/HDB",
            "CredentialType": "ADMIN",
            "SecretId": "sim2real-fake-secret-id-for-validation-only",
        }
    ]

    err = _error(
        lambda: client.register_application(
            ApplicationId=abap_id,
            ApplicationType="SAP_ABAP",
            Instances=[instance_id],
            Sid="ABC",
            Credentials=credentials,
        ),
        expect="a SAP_ABAP RegisterApplication call carrying Credentials",
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected = (
        "The SID and database ARN of ASCS or Application Server must be specified for SAP "
        "applications with type SAP_ABAP."
    )
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    # effect absent: the rejected SAP_ABAP registration did not create an app. ssm-sap answers an
    # unregistered ApplicationId with ValidationException, not ResourceNotFoundException.
    not_found = _error(
        lambda: client.get_application(ApplicationId=abap_id),
        expect=f"GetApplication({abap_id!r}) for a SAP_ABAP registration that was rejected",
    )
    assert not_found["Code"] == "ValidationException", (
        f"expected the rejected registration to leave no application (ValidationException on "
        f"GetApplication), got {not_found!r}"
    )
    expected_absent = f"No registered application found for account: {ctx.account}, and application: {abap_id}"
    assert not_found.get("Message") == expected_absent, (
        f"expected message {expected_absent!r}, got {not_found.get('Message')!r}"
    )

    # positive control: the same Credentials shape is valid for HANA
    hana_id = ctx.unique_name("sim2real-sap-hana-").replace("_", "-")[:60]
    hana_instance = "i-" + secrets.token_hex(9)[:17]
    resp = _register_application_with_role_propagation_retry(
        client,
        ApplicationId=hana_id,
        ApplicationType="HANA",
        Instances=[hana_instance],
        Sid="HDB",
        SapInstanceNumber="00",
        Credentials=credentials,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _deregister_ignore_errors(ctx, hana_id))
    assert resp["Application"]["Id"] == hana_id, (
        f"RegisterApplication echoed Id {resp['Application'].get('Id')!r}, expected {hana_id!r}"
    )
    # terminal read: independent GetApplication, not the mutating call's own response
    got = client.get_application(ApplicationId=hana_id)
    assert got["Application"]["Id"] == hana_id, (
        f"GetApplication({hana_id!r}) returned Id {got['Application'].get('Id')!r}"
    )
    assert got["Application"]["Type"] == "HANA", (
        f"expected Type HANA for the accepted HANA-with-Credentials registration, "
        f"got {got['Application'].get('Type')!r}"
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
            return
        except ClientError:
            time.sleep(5.0)
    raise AssertionError(
        "AWSServiceRoleForAWSSSMForSAP did not become visible via iam:GetRole within 60s of creation"
    )


def _register_application_with_role_propagation_retry(client, **kwargs):
    """RegisterApplication for a type that actually creates the app (HANA here) makes ssm-sap
    assume AWSServiceRoleForAWSSSMForSAP internally. Real AWS answers a freshly created SLR with
    ValidationException("...allow a few minutes for it to propagate before retrying") -- confirmed
    against real AWS, not assumed -- so this is a bounded retry on that specific, named condition,
    never a blind sleep."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return client.register_application(**kwargs)
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] != "ValidationException" or "propagate" not in err.get("Message", ""):
                raise
            last_exc = e
            time.sleep(2)
    raise AssertionError(
        f"AWSServiceRoleForAWSSSMForSAP still not usable by RegisterApplication after 180s: {last_exc}"
    )


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


def _error(fn, *, expect: str):
    """Call fn(); return its botocore error dict (Code, Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available and
    must not be reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected {expect} to be rejected, but it SUCCEEDED with {result!r}")


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
