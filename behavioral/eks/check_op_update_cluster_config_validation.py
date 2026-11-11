"""op-update-cluster-config-validation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")

CHECK = "op-update-cluster-config-validation"
GROUP = 'overly-permissive'
SERVICES = ['eks']

_ALL_LOG_TYPES = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] UpdateClusterConfig resolves the cluster BEFORE validating the logging body: even an unknown log type on a missing cluster reports ResourceNotFoundException, so an emulator must not answer InvalidParameterException here."""
    c = ctx.client("eks")
    ghost = ctx.unique_name("sim2real-behav-eks-ghost-")

    # An unknown log-type enum does NOT pre-empt the cluster lookup.
    code, msg = _expect_error(
        lambda: c.update_cluster_config(
            name=ghost,
            logging={"clusterLogging": [{"types": ["definitely-not-a-log-type"], "enabled": True}]},
        )
    )
    assert code == "ResourceNotFoundException", f"bad log type -> {code}: {msg}"
    assert msg == f"No cluster found for name: {ghost}.", f"bad log type -> {msg!r}"

    # A well-formed logging payload against a missing cluster agrees.
    code, msg = _expect_error(
        lambda: c.update_cluster_config(
            name=ghost,
            logging={"clusterLogging": [{"types": _ALL_LOG_TYPES, "enabled": True}]},
        )
    )
    assert code == "ResourceNotFoundException", f"{code}: {msg}"
    assert msg == f"No cluster found for name: {ghost}.", f"{msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
