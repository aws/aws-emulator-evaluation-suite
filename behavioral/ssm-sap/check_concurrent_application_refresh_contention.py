"""concurrent-application-refresh-contention."""
from __future__ import annotations

import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-application-refresh-contention"
GROUP = "concurrency"
SERVICES = ["ssm-sap"]

_UUID_RE = re.compile(r"^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent StartApplicationRefresh calls on an application whose registration FAILED are
    each rejected with the same ConflictException, and any call that succeeds returns a unique
    UUID-shaped OperationId: racing calls do not corrupt state."""
    _ensure_service_linked_role(ctx)
    _purge_stale_apps(ctx)
    client = ctx.client("ssm-sap")
    app_id = ctx.unique_name("sim2real-sap-").replace("_", "-")[:60]
    instance_id = "i-" + secrets.token_hex(9)[:17]

    client.register_application(
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

    # StartApplicationRefresh requires the application to have left
    # REGISTERING (it settles to FAILED, since the backing instance is
    # fake) -- wait for that before racing refresh calls against it.
    deadline_settle = time.monotonic() + 180.0
    status = None
    while time.monotonic() < deadline_settle:
        status = client.get_application(ApplicationId=app_id)["Application"]["Status"]
        if status != "REGISTERING":
            break
        time.sleep(2)
    assert status != "REGISTERING", (
        f"application never left REGISTERING within 180s, still {status!r}"
    )

    def _list_operation_ids():
        ids = set()
        token = None
        while True:
            kwargs = {"NextToken": token} if token else {}
            page = client.list_operations(ApplicationId=app_id, **kwargs)
            ids.update(op["Id"] for op in page.get("Operations", []))
            token = page.get("NextToken")
            if not token:
                break
        return ids

    operations_before = _list_operation_ids()

    def _refresh_once():
        from botocore.exceptions import ClientError

        try:
            resp = client.start_application_refresh(ApplicationId=app_id)
            return ("ok", resp["OperationId"])
        except ClientError as e:
            return ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(_refresh_once) for _ in range(5)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for kind, r in results if kind == "ok"]
    errors = [r for kind, r in results if kind == "error"]

    for op_id in successes:
        assert _UUID_RE.match(op_id), f"malformed OperationId {op_id!r}"
    assert len(successes) == len(set(successes)), "duplicate OperationId across racers"

    # StartApplicationRefresh on an application whose registration ended in
    # FAILED (as ours always does, with a fake backing instance) is
    # rejected uniformly with ConflictException for every racer -- the
    # concurrency guarantee under test is that a broken precondition
    # produces one deterministic error family, never a mix of errors or an
    # unhandled exception, regardless of how many callers race it.
    assert len(errors) == len(results), (
        f"expected every racer to be rejected the same way, got "
        f"{len(successes)} unexpected successes among {results}"
    )
    for err_code, err_message in errors:
        assert err_code == "ConflictException", err_code
        assert err_message == "The specified application has not been registered successfully", err_message

    # The rejection response is not enough on its own -- a target could
    # answer ConflictException while still recording an operation behind the
    # scenes. Read the application's own operation history (an independent
    # call from the mutating one) and require that the set of operation ids
    # is unchanged: none of the rejected racers left anything behind.
    operations_after = _list_operation_ids()
    new_operation_ids = operations_after - operations_before
    assert not new_operation_ids, (
        f"rejected StartApplicationRefresh calls left new operation(s) "
        f"behind: {sorted(new_operation_ids)}"
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
    # A freshly created service-linked role is readable via IAM before it has
    # propagated far enough for ssm-sap to accept it -- require the read to
    # succeed repeatedly over a bounded window instead of trusting one read
    # (or an unconditional sleep) before racing calls against the role.
    deadline = time.monotonic() + 90.0
    consecutive_ok = 0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName="AWSServiceRoleForAWSSSMForSAP")
        except ClientError:
            consecutive_ok = 0
            time.sleep(5.0)
            continue
        consecutive_ok += 1
        if consecutive_ok >= 3:
            return
        time.sleep(5.0)
    raise AssertionError(
        "service-linked role AWSServiceRoleForAWSSSMForSAP never stabilised within 90s"
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
