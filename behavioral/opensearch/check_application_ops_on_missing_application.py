"""application-ops-on-missing-application."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-ops-on-missing-application"
GROUP = 'application'
SERVICES = ['opensearch']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get/UpdateApplication on a well-formed nonexistent id fail with ResourceNotFoundException and
    the exact message and DeleteApplication on it succeeds; on a real application all three succeed and
    a repeat delete succeeds or fails with ConflictException and the exact message."""
    os = ctx.client('opensearch')

    # Positive control: a real application. Ids are server-assigned at CreateApplication
    # time, so a fabricated id below can never coincidentally collide with it.
    app_name = ctx.unique_name('sim2real-appmiss-')[:30].rstrip('-')
    created = os.create_application(name=app_name, tagList=[{'Key': 'sim2real', 'Value': 'app-ops-on-missing-application'}])
    real_id = created['id']
    ctx.on_cleanup(lambda: _delete_if_present(os, real_id))
    _wait_active(os, real_id)

    got = os.get_application(id=real_id)
    assert got['name'] == app_name, f'positive control: GetApplication did not echo name: {got!r}'

    os.update_application(
        id=real_id,
        appConfigs=[{'key': 'opensearchDashboards.dashboardAdmin.users', 'value': 'sim2real-audit-marker'}],
    )
    updated = os.get_application(id=real_id)
    configs = {c['key']: c['value'] for c in updated.get('appConfigs', [])}
    assert configs.get('opensearchDashboards.dashboardAdmin.users') == 'sim2real-audit-marker', (
        f'positive control: UpdateApplication did not apply: {updated!r}'
    )

    # A well-formed id (matches the service's own ^[a-z0-9]{3,30}$ pattern) that was never
    # created by anything -- this is a "nonexistent id", not a malformed one.
    bogus_id = ctx.unique_name('s2r')

    code, message = _client_error(lambda: os.get_application(id=bogus_id))
    assert code == 'ResourceNotFoundException', f'GetApplication: got {code}'
    expected = 'Application does not exist'
    assert message == expected, f'GetApplication message: expected {expected!r}, got {message!r}'

    code, message = _client_error(lambda: os.update_application(
        id=bogus_id,
        appConfigs=[{'key': 'opensearchDashboards.dashboardAdmin.users', 'value': 'sim2real-audit-marker'}],
    ))
    assert code == 'ResourceNotFoundException', f'UpdateApplication: got {code}'
    expected = 'Application does not exist'
    assert message == expected, f'UpdateApplication message: expected {expected!r}, got {message!r}'

    # DeleteApplication on a nonexistent id is idempotent: it returns normally.
    os.delete_application(id=bogus_id)

    # Positive control completes: DeleteApplication succeeds against the real application.
    # A repeat delete right after is a *different* case from the never-existed id above --
    # the application is now asynchronously transitioning (DELETING), so real AWS answers
    # either ConflictException (still mid-delete) or the same idempotent no-op (already
    # gone by the time this call lands), never a resource-bearing success.
    os.delete_application(id=real_id)
    try:
        os.delete_application(id=real_id)
    except ClientError as exc:
        redelete_code = exc.response['Error']['Code']
        assert redelete_code == 'ConflictException', (
            f'repeat DeleteApplication on an in-flight delete must be idempotent or a conflict, got {redelete_code}'
        )
        expected = 'Application has an operation in progress. Please wait for it to finish.'
        redelete_message = exc.response['Error'].get('Message', '')
        assert redelete_message == expected, (
            f'repeat DeleteApplication conflict message: expected {expected!r}, got {redelete_message!r}'
        )


def _client_error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message', '')
    raise AssertionError(f'expected a rejection, but the call SUCCEEDED and returned {result!r}')


def _delete_if_present(os, app_id):
    """Delete the application and wait until GetApplication answers ResourceNotFoundException:
    DeleteApplication is asynchronous, and ConflictException (an operation in progress) is
    retried every 2 s. Raises at the 900 s teardown deadline."""
    deadline = time.monotonic() + 900.0
    while True:
        try:
            os.delete_application(id=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
                raise
        try:
            status = os.get_application(id=app_id).get("status")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"application {app_id} is still {status!r} at the teardown deadline")
        time.sleep(2)


def _wait_active(os, app_id, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = os.get_application(id=app_id).get('status')
        if status in {'ACTIVE', 'FAILED'}:
            break
        time.sleep(3)
    else:
        raise AssertionError(f'application {app_id} did not leave provisioning within {timeout_s}s (last={status!r})')
    assert status == 'ACTIVE', f'expected application to become ACTIVE, got {status}'


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
