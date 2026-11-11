"""op-start-nonexistent-recorder."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected StartConfigurationRecorder on a nonexistent recorder to be "
        f"rejected, but it SUCCEEDED and returned {result!r}"
    )

CHECK = "op-start-nonexistent-recorder"
GROUP = 'overly-permissive'
SERVICES = ['config']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """StartConfigurationRecorder against a recorder name that does not
    exist must fail with NoSuchConfigurationRecorderException -- the service
    must not auto-create or silently ignore the target."""
    cfg = ctx.client("config")
    missing = ctx.unique_name("sim2real-behav-cfg-absent-recorder-")
    code, message = _error(
        lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=missing)
    )
    assert code == "NoSuchConfigurationRecorderException", (
        f"expected NoSuchConfigurationRecorderException, got {code}"
    )
    assert message == (
        "The name of the configuration recorder you entered cannot be found. "
        "Verify the configuration recorder name, and try again."
    ), message

    recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
    assert all(r["name"] != missing for r in recorders), (
        f"missing recorder {missing!r} unexpectedly present: {recorders}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
