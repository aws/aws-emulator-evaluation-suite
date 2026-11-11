"""get-model-invocation-logging-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-model-invocation-logging-config"
GROUP = 'model_access'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """After DeleteModelInvocationLoggingConfiguration, GetModelInvocationLoggingConfiguration omits the
    loggingConfig field entirely (not merely falsy), whether or not a configuration existed before;
    any original configuration is restored in cleanup."""
    bc = ctx.client("bedrock")

    original = bc.get_model_invocation_logging_configuration().get("loggingConfig")

    def _restore():
        if original:
            bc.put_model_invocation_logging_configuration(loggingConfig=original)

    ctx.on_cleanup(_restore)

    bc.delete_model_invocation_logging_configuration()

    resp = bc.get_model_invocation_logging_configuration()
    assert "loggingConfig" not in resp, (
        "expected GetModelInvocationLoggingConfiguration to omit loggingConfig "
        f"entirely once reset to the default state, got keys {sorted(resp.keys())} "
        f"with value {resp.get('loggingConfig')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
