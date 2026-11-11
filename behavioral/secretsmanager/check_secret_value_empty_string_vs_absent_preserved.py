"""secret-value-empty-string-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "secret-value-empty-string-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSecretValue omits an unset SecretString or SecretBinary entirely rather than returning
    null or empty, and the supplied field round-trips unchanged. Both fields have a minimum
    length of 1, so an empty string cannot be stored."""
    sm = ctx.client("secretsmanager")

    tags_kwarg = [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]

    name_str_only = ctx.unique_name("sim2real-behav-fieldstr-")
    sm.create_secret(Name=name_str_only, SecretString="only-string-value", Tags=tags_kwarg)
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=name_str_only, ForceDeleteWithoutRecovery=True)
    )
    resp_str = sm.get_secret_value(SecretId=name_str_only)
    assert resp_str["SecretString"] == "only-string-value", (
        f"expected SecretString='only-string-value', got {resp_str['SecretString']!r}"
    )
    assert "SecretBinary" not in resp_str, "unset SecretBinary must be absent, not null/empty"

    name_bin_only = ctx.unique_name("sim2real-behav-fieldbin-")
    sm.create_secret(Name=name_bin_only, SecretBinary=b"only-binary-value", Tags=tags_kwarg)
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=name_bin_only, ForceDeleteWithoutRecovery=True)
    )
    resp_bin = sm.get_secret_value(SecretId=name_bin_only)
    assert resp_bin["SecretBinary"] == b"only-binary-value", (
        f"expected SecretBinary=b'only-binary-value', got {resp_bin['SecretBinary']!r}"
    )
    assert "SecretString" not in resp_bin, "unset SecretString must be absent, not null/empty"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
