"""qev2-idc-application-concurrent-modify-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "qev2-idc-application-concurrent-modify-conflict"
GROUP = "concurrency"
SERVICES = ["redshift"]

MSG_APP_NOT_EXISTS = "The Qev2IdcApplication you specified doesn't exist."


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:identity-center-instance",
)
def run(ctx) -> None:
    """Of two concurrent DeleteQev2IdcApplication calls on one application at least one succeeds (a
    loser answers InvalidParameterValue with the not-exists message); afterwards it is unlisted and
    a further delete answers Qev2IdcApplicationNotExists."""
    sso_admin = ctx.client("sso-admin")
    idc_instance_arn = _idc_instance(ctx, sso_admin)

    redshift = ctx.client("redshift")

    app_name = ctx.unique_name("sim2real-behav-qev2-")
    try:
        created = redshift.create_qev2_idc_application(
            IdcInstanceArn=idc_instance_arn,
            Qev2IdcApplicationName=app_name,
            IdcDisplayName=app_name,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code in {"DependentServiceAccessDenied", "DependentServiceUnavailableFault"}:
            raise AssertionError(
                f"CreateQev2IdcApplication was rejected by the dependent IdC service "
                f"with {code}; this account/role lacks the setup needed to run the race"
            ) from exc
        raise
    app_arn = created["Qev2IdcApplication"]["Qev2IdcApplicationArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(redshift, app_arn))

    results: list[tuple[bool, str | None, str | None]] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_try_delete, redshift, app_arn) for _ in range(2)
        ]
        for fut in futures:
            results.append(fut.result())

    successes = [ok for ok, _code, _message in results if ok]
    failures = [(code, message) for ok, code, message in results if not ok]

    assert len(successes) >= 1, f"expected at least one concurrent delete to succeed, got {results}"
    # Which refusal a race loser sees depends on how far the winner got, so each loser is
    # graded against the message of the code it drew.
    for failure_code, failure_message in failures:
        if failure_code == "Qev2IdcApplicationNotExists":
            assert failure_message == MSG_APP_NOT_EXISTS, (
                f"expected {MSG_APP_NOT_EXISTS!r}, got {failure_message!r}"
            )
        else:
            # message varies: the IdC refusal embeds a per-request SsoAdmin request id
            assert failure_code == "InvalidParameterValue", (
                f"unexpected error code from a concurrent delete loser: {failure_code!r}, "
                f"results={results}"
            )
    assert not _still_listed(redshift, app_arn), (
        "the raced application is still visible via an independent DescribeQev2IdcApplications "
        "read after the concurrent deletes settled"
    )
    settle_code, settle_message = _refusal(
        lambda: redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)
    )
    assert settle_code == "Qev2IdcApplicationNotExists", settle_code
    assert settle_message == MSG_APP_NOT_EXISTS, f"expected {MSG_APP_NOT_EXISTS!r}, got {settle_message!r}"

    # Positive control: create-then-delete (no race) still works normally.
    control_name = ctx.unique_name("sim2real-behav-qev2-ctl-")
    control = redshift.create_qev2_idc_application(
        IdcInstanceArn=idc_instance_arn,
        Qev2IdcApplicationName=control_name,
        IdcDisplayName=control_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    control_arn = control["Qev2IdcApplication"]["Qev2IdcApplicationArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(redshift, control_arn))
    assert _still_listed(redshift, control_arn), (
        "freshly created control application is not visible via an independent "
        "DescribeQev2IdcApplications read"
    )
    redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=control_arn)
    code, message = _refusal(
        lambda: redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=control_arn)
    )
    assert code == "Qev2IdcApplicationNotExists", code
    assert message == MSG_APP_NOT_EXISTS, f"expected {MSG_APP_NOT_EXISTS!r}, got {message!r}"
    assert not _still_listed(redshift, control_arn), (
        "the double-deleted control application is still visible via an independent "
        "DescribeQev2IdcApplications read"
    )


def _idc_instance(ctx, sso_admin) -> str:
    """The account's ACTIVE IAM Identity Center instance. An account holds at most one, so an
    existing instance it owns is adopted and left in place; only when there is none does the
    check create its own and register that instance's deletion."""
    owned = [
        i for i in sso_admin.list_instances().get("Instances", [])
        if i.get("OwnerAccountId", ctx.account) == ctx.account and i.get("Status") != "DELETE_IN_PROGRESS"
    ]
    if owned:
        instance_arn = owned[0]["InstanceArn"]
    else:
        try:
            instance_arn = sso_admin.create_instance(
                Name=ctx.unique_name("sim2real-behav-idc-"),
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )["InstanceArn"]
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"CreateInstance failed with {_error_code_from_exc(exc)}; this account cannot "
                f"host an IAM Identity Center instance for the race"
            ) from exc
        ctx.on_cleanup(lambda: _delete_instance_ignore_missing(sso_admin, instance_arn))

    deadline = time.monotonic() + 120
    while True:
        instances = sso_admin.list_instances().get("Instances", [])
        status = next(i["Status"] for i in instances if i["InstanceArn"] == instance_arn)
        if status == "ACTIVE":
            return instance_arn
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"IAM Identity Center instance {instance_arn} never reached ACTIVE within 120s "
                f"(last status={status!r})"
            )
        time.sleep(5)


def _delete_instance_ignore_missing(sso_admin, instance_arn: str) -> None:
    try:
        sso_admin.delete_instance(InstanceArn=instance_arn)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise


def _try_delete(redshift, app_arn: str) -> tuple[bool, str | None, str | None]:
    try:
        redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)
        return True, None, None
    except Exception as exc:  # noqa: BLE001
        return False, _error_code_from_exc(exc), _error_message_from_exc(exc)


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``.

    A call that succeeds raises ``AssertionError``: the refusal is the claim."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code is None:
            raise
        return code, _error_message_from_exc(exc)
    raise AssertionError(f"expected a refusal, the call succeeded with {result!r}")


def _still_listed(redshift, app_arn: str) -> bool:
    try:
        resp = redshift.describe_qev2_idc_applications(Qev2IdcApplicationArn=app_arn)
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code == "Qev2IdcApplicationNotExists":
            return False
        raise
    return any(
        a["Qev2IdcApplicationArn"] == app_arn
        for a in resp.get("Qev2IdcApplications", [])
    )


def _error_code_from_exc(exc) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _error_message_from_exc(exc) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Message")


def _delete_ignore_missing(redshift, app_arn: str) -> None:
    try:
        redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "Qev2IdcApplicationNotExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
