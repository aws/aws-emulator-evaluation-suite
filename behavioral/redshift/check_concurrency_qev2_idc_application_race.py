"""concurrency-qev2-idc-application-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrency-qev2-idc-application-race"
GROUP = "concurrency"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Concurrent Modify/Delete on one Qev2IdcApplication never leave a partially-applied mix: at
    least one succeeds, a loser is refused with InvalidParameterValue or Qev2IdcApplicationNotExists
    (exact message), and the final state matches the winners.
    """

    instances = _identity_center_instances(ctx)
    idc_instance_arn = instances[0]["InstanceArn"]

    redshift = ctx.client("redshift")
    app_name = ctx.unique_name("sim2real-qev2-").lower().replace("_", "-")
    display_name = ctx.unique_name("sim2real-qev2-disp-")

    created = redshift.create_qev2_idc_application(
        IdcInstanceArn=idc_instance_arn,
        Qev2IdcApplicationName=app_name,
        IdcDisplayName=display_name,
    )["Qev2IdcApplication"]
    app_arn = created["Qev2IdcApplicationArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(redshift, app_arn))

    new_display_name = ctx.unique_name("sim2real-qev2-disp2-")
    with ThreadPoolExecutor(max_workers=2) as pool:
        modify_future = pool.submit(
            redshift.modify_qev2_idc_application,
            Qev2IdcApplicationArn=app_arn,
            IdcDisplayName=new_display_name,
        )
        delete_future = pool.submit(
            redshift.delete_qev2_idc_application, Qev2IdcApplicationArn=app_arn
        )
        modify_result, modify_error = _resolve(modify_future)
        delete_result, delete_error = _resolve(delete_future)

    assert modify_error is None or delete_error is None, (
        f"both concurrent calls were refused: modify={modify_error!r} delete={delete_error!r}"
    )

    if modify_error is not None:
        code = modify_error.response["Error"]["Code"]
        if code == "Qev2IdcApplicationNotExists":
            # The modify arrived after the delete had removed the application.
            expected = (
                "The Qev2IdcApplication you specified doesn't exist or the status isn't Completed."
            )
            message = modify_error.response["Error"].get("Message")
            assert message == expected, f"expected {expected!r}, got {message!r}"
        else:
            _assert_in_flight_refusal(modify_error)
    else:
        shown = modify_result["Qev2IdcApplication"]["IdcDisplayName"]
        assert shown == new_display_name, (
            f"modify succeeded but reported display name {shown!r}, expected {new_display_name!r}"
        )

    if delete_error is not None:
        _assert_in_flight_refusal(delete_error)

    listed = [
        a
        for a in redshift.describe_qev2_idc_applications().get("Qev2IdcApplications", [])
        if a["Qev2IdcApplicationArn"] == app_arn
    ]
    if delete_error is None:
        assert not listed, "DeleteQev2IdcApplication succeeded but the application is still listed"
    else:
        assert len(listed) == 1, f"the refused delete removed the application anyway: {listed!r}"
        expected_name = new_display_name if modify_error is None else display_name
        assert listed[0]["IdcDisplayName"] == expected_name, (
            f"expected display name {expected_name!r}, got {listed[0]['IdcDisplayName']!r}"
        )


def _assert_in_flight_refusal(exc) -> None:
    """A call refused because the other call's Identity Center request is in flight."""
    assert exc.response["Error"]["Code"] == "InvalidParameterValue", exc
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc
    # message varies: it embeds the per-request id of the downstream Identity Center call


# ===== helpers (self-contained) =====

def _identity_center_instances(ctx):
    """The account's IAM Identity Center instances, creating one if the account has none.

    `sso-admin:CreateInstance` provisions a
    STANDALONE (non-Organizations) instance, so the prerequisite is satisfiable in-check in any
    account. Exactly one instance is
    allowed per account and deleting it would disrupt any other check relying on it, so one created
    here is deliberately never torn down.
    """
    import time

    from botocore.exceptions import ClientError

    sso_idc = ctx.client("sso-admin")
    try:
        instances = sso_idc.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']})"
        ) from exc
    if not instances:
        sso_idc.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    deadline = time.time() + 120
    while time.time() < deadline:
        found = sso_idc.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        if any(i.get("Status") == "ACTIVE" and "IdentityStoreId" in i for i in found):
            return found
        time.sleep(3)
    raise AssertionError(
        "IAM Identity Center instance did not become ACTIVE with an IdentityStoreId within 120s"
    )

def _resolve(future):
    try:
        return future.result(), None
    except ClientError as exc:
        return None, exc


def _best_effort_delete(redshift, app_arn: str) -> None:
    try:
        redshift.delete_qev2_idc_application(Qev2IdcApplicationArn=app_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "Qev2IdcApplicationNotExists":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
