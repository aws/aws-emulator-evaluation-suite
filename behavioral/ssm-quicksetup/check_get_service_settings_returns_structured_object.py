"""get-service-settings-returns-structured-object."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-service-settings-returns-structured-object"
GROUP = "settings"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetServiceSettings always returns a ServiceSettings object (even if the account has never
    configured Explorer-enabling), and when ExplorerEnablingRoleArn is present it is a
    syntactically valid IAM role ARN string."""
    qs = ctx.client("ssm-quicksetup")
    resp = qs.get_service_settings()
    assert "ServiceSettings" in resp, f"GetServiceSettings response missing ServiceSettings key: {resp!r}"
    settings = resp["ServiceSettings"]
    assert isinstance(settings, dict), f"expected ServiceSettings to be an object, got {type(settings).__name__}: {settings!r}"

    role_arn = settings.get("ExplorerEnablingRoleArn")
    if role_arn is not None:
        assert role_arn.startswith("arn:aws:iam::") and ":role/" in role_arn, (
            f"expected ExplorerEnablingRoleArn to be a well-formed IAM role ARN, got {role_arn!r}"
        )

    # calling it twice in a row must be stable (idempotent read, no side effects)
    resp2 = qs.get_service_settings()
    role_arn2 = resp2["ServiceSettings"].get("ExplorerEnablingRoleArn")
    assert role_arn2 == role_arn, (
        f"GetServiceSettings was not stable across two immediate reads: first call returned "
        f"ExplorerEnablingRoleArn={role_arn!r}, second call returned {role_arn2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
