"""create-maintenance-window-rejects-idempotency-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-maintenance-window-rejects-idempotency-mismatch"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Replaying CreateMaintenanceWindow with the same ClientToken and parameters returns the same
    WindowId, while the same token with another Name fails with IdempotentParameterMismatch (empty
    message) and creates no second window."""

    ssm = ctx.client("ssm")

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")

    def _track_maintenance_window(window_id):
        ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
        return window_id

    token = ctx.unique_name("sim2real-behav-token-")
    name_a = ctx.unique_name("sim2real-behav-probe-mw-")
    name_b = ctx.unique_name("sim2real-behav-probe-mw-")

    create_kwargs = dict(
        Name=name_a,
        Schedule="cron(0 10 * * ? *)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=True,
        ClientToken=token,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    create_resp = ssm.create_maintenance_window(**create_kwargs)
    window_id = create_resp["WindowId"]
    _track_maintenance_window(window_id)

    # Positive control: replaying the exact same request with the same token is
    # idempotent and returns the same window, not a second one.
    replay_resp = ssm.create_maintenance_window(**create_kwargs)
    assert replay_resp["WindowId"] == window_id, (
        f"expected idempotent replay to return the original WindowId {window_id!r}, "
        f"got {replay_resp['WindowId']!r}"
    )

    # Break exactly one thing: reuse the same token with a different Name.
    code, message = _error(
        lambda: ssm.create_maintenance_window(
            Name=name_b,
            Schedule="cron(0 10 * * ? *)",
            Duration=2,
            Cutoff=1,
            AllowUnassociatedTargets=True,
            ClientToken=token,
        )
    )
    assert code == "IdempotentParameterMismatch", (
        f"expected IdempotentParameterMismatch for a token reused with different "
        f"params, got {code!r}"
    )
    # AWS answers this refusal with an empty message.
    assert message == "", f"CreateMaintenanceWindow message: {message!r}"

    # The listing is account-wide; each read is scoped by this run's own window names.
    named_b = ssm.describe_maintenance_windows(
        Filters=[{"Key": "Name", "Values": [name_b]}]
    )["WindowIdentities"]
    assert named_b == [], (
        f"mismatched-token create for {name_b!r} must not have taken effect: {named_b!r}"
    )
    named_a = ssm.describe_maintenance_windows(
        Filters=[{"Key": "Name", "Values": [name_a]}]
    )["WindowIdentities"]
    assert [w["WindowId"] for w in named_a] == [window_id], (
        f"original window {window_id!r} must still exist, alone under its name: {named_a!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
