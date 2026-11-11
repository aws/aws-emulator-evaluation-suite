"""snapshot-of-ready-application-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "snapshot-of-ready-application-rejected"
GROUP = 'rejected-state-transition'
SERVICES = ['kinesisanalyticsv2']

RUNTIME = "FLINK-1_15"

# DeleteApplicationSnapshot requires a creation timestamp for a snapshot that, here, was never
# minted. Any value is as wrong as any other, so this one is fixed rather than drawn from the clock.
_SNAPSHOT_TIMESTAMP = 1700000000

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "kinesisanalytics.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

def _error(fn) -> dict:
    """The AWS error (``Code`` and ``Message``) raised by ``fn``.

    Raises if the call SUCCEEDS: an emulator that snapshots a stopped application is exactly the
    over-permissiveness this check exists to catch, and a sentinel return would hide it.
    """
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if not response:
            raise
        return response["Error"]
    raise AssertionError("call unexpectedly SUCCEEDED where real AWS rejects it")


def _create_application(ctx, kda, **kwargs) -> dict:
    """CreateApplication, retrying only the IAM-propagation refusal for up to 150 s.

    A role created seconds earlier is not yet assumable by the service, which reports
    `InvalidArgumentException: ... doesn't have sufficient privileges to assume the role`.
    """
    deadline = time.monotonic() + 150
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            return kda.create_application(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "sufficient privileges to assume the role" not in msg:
                raise
            last = msg
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"CreateApplication never stopped reporting a non-assumable role: {last}")
        time.sleep(2)


def _delete_application(kda, app: str) -> None:
    detail = kda.describe_application(ApplicationName=app)["ApplicationDetail"]
    if detail["ApplicationStatus"] != "DELETING":
        kda.delete_application(ApplicationName=app, CreateTimestamp=detail["CreateTimestamp"])


def _snapshots(kda, app: str) -> list[str]:
    names = []
    token = None
    while True:
        kwargs = {"ApplicationName": app, "Limit": 50}
        if token:
            kwargs["NextToken"] = token
        page = kda.list_application_snapshots(**kwargs)
        names += [s["SnapshotName"] for s in page.get("SnapshotSummaries", [])]
        token = page.get("NextToken")
        if not token:
            return sorted(names)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Snapshotting a READY application is refused as a state error, and creates no snapshot.

    The same call on a nonexistent application is refused with a different code, and the
    application's own control plane stays healthy throughout.
    """
    kda = ctx.client("kinesisanalyticsv2")
    iam = ctx.client("iam")

    app = ctx.unique_name("sim2real-behav-kdav2-")
    absent = ctx.unique_name("sim2real-behav-kdav2-absent-")
    role_name = ctx.unique_name("sim2real-behav-kdav2-")
    snapshot = "sim2real-behav-snap-1"

    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    created = _create_application(
        ctx, kda,
        ApplicationName=app,
        RuntimeEnvironment=RUNTIME,
        ServiceExecutionRole=role["Role"]["Arn"],
        ApplicationDescription="sim2real behavioral state-transition check",
        ApplicationConfiguration={"ApplicationSnapshotConfiguration": {"SnapshotsEnabled": True}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_application(kda, app))
    snapshots_enabled = created["ApplicationDetail"]["ApplicationConfigurationDescription"][
        "ApplicationSnapshotConfigurationDescription"]["SnapshotsEnabled"]
    assert snapshots_enabled is True, (
        f"the application was created with SnapshotsEnabled={snapshots_enabled!r}; the refusal "
        f"below must be about the application's STATE, not about snapshots being disabled"
    )
    assert created["ApplicationDetail"]["ApplicationStatus"] == "READY", (
        f"a created-but-never-started application reported "
        f"{created['ApplicationDetail']['ApplicationStatus']!r}, expected 'READY'"
    )
    assert _snapshots(kda, app) == [], (
        f"a newly created application already has snapshots: {_snapshots(kda, app)!r}"
    )

    err = _error(lambda: kda.create_application_snapshot(
        ApplicationName=app, SnapshotName=snapshot))
    code = err["Code"]
    assert code == "InvalidRequestException", (
        f"snapshotting a READY application was refused with {code!r}, "
        f"expected 'InvalidRequestException'"
    )
    expected = (
        f"Application {app} is in READY status. Snapshot creation is only allowed when "
        f"application is in RUNNING status"
    )
    assert err["Message"] == expected, (
        f"snapshotting a READY application was refused with message {err['Message']!r}, "
        f"expected {expected!r}"
    )
    assert _snapshots(kda, app) == [], (
        f"the refused CreateApplicationSnapshot still minted a snapshot record: "
        f"{_snapshots(kda, app)!r}"
    )
    missing_snapshot = f"Snapshot '{snapshot}' does not exist for application {app}."
    describe_err = _error(lambda: kda.describe_application_snapshot(
        ApplicationName=app, SnapshotName=snapshot))
    describe_code = describe_err["Code"]
    assert describe_code == "ResourceNotFoundException", (
        f"describing the snapshot that was refused reported {describe_code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    assert describe_err["Message"] == missing_snapshot, (
        f"describing the snapshot that was refused reported message "
        f"{describe_err['Message']!r}, expected {missing_snapshot!r}"
    )
    delete_err = _error(lambda: kda.delete_application_snapshot(
        ApplicationName=app, SnapshotName=snapshot,
        SnapshotCreationTimestamp=_SNAPSHOT_TIMESTAMP))
    assert delete_err["Code"] == "ResourceNotFoundException", (
        f"deleting the snapshot that was never minted reported {delete_err['Code']!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    assert delete_err["Message"] == missing_snapshot, (
        f"deleting the snapshot that was never minted reported message "
        f"{delete_err['Message']!r}, expected {missing_snapshot!r}"
    )

    # The missing SNAPSHOT and the missing APPLICATION are two different conditions on the very
    # same operation, and real AWS reports them with two different codes. An emulator that answers
    # one code for "something you named is not there" passes neither assertion.
    absent_snapshot_err = _error(lambda: kda.describe_application_snapshot(
        ApplicationName=absent, SnapshotName=snapshot))
    absent_snapshot_code = absent_snapshot_err["Code"]
    assert absent_snapshot_code == "InvalidArgumentException", (
        f"describing a snapshot of an application that does not exist reported "
        f"{absent_snapshot_code!r}, expected 'InvalidArgumentException'"
    )
    expected = f"Application '{absent}' does not exist under account '{ctx.account}'."
    assert absent_snapshot_err["Message"] == expected, (
        f"describing a snapshot of an application that does not exist reported message "
        f"{absent_snapshot_err['Message']!r}, expected {expected!r}"
    )
    assert absent_snapshot_code != describe_code, (
        f"DescribeApplicationSnapshot reported {describe_code!r} both for a missing snapshot of a "
        f"real application and for a missing application; real AWS separates the two"
    )

    # The same call against an application that does not exist must NOT collapse into the same
    # error: one catch-all code would let an emulator pass both assertions above for free.
    absent_err = _error(lambda: kda.create_application_snapshot(
        ApplicationName=absent, SnapshotName=snapshot))
    absent_code = absent_err["Code"]
    assert absent_code == "InvalidArgumentException", (
        f"snapshotting an application that does not exist reported {absent_code!r}, "
        f"expected 'InvalidArgumentException'"
    )
    expected = f"Application {absent} does not exist under accountId {ctx.account}"
    assert absent_err["Message"] == expected, (
        f"snapshotting an application that does not exist reported message "
        f"{absent_err['Message']!r}, expected {expected!r}"
    )
    assert absent_code != code, (
        f"both the READY application and the absent application were refused with {code!r}; "
        f"real AWS distinguishes the state error from the missing-application error"
    )

    # Positive control: the same application's control plane still answers, unchanged.
    detail = kda.describe_application(ApplicationName=app)["ApplicationDetail"]
    assert detail["ApplicationStatus"] == "READY", (
        f"after the refusals the application is {detail['ApplicationStatus']!r}, expected 'READY'"
    )
    assert detail["ApplicationVersionId"] == 1, (
        f"the refusals advanced the version pointer to {detail['ApplicationVersionId']!r}, "
        f"expected 1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
