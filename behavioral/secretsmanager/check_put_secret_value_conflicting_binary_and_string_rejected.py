"""put-secret-value-conflicting-binary-and-string-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-secret-value-conflicting-binary-and-string-rejected"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSecretValue rejects a call that supplies both SecretBinary and SecretString, and
    leaves the current version untouched."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-putconflict-")

    create_resp = sm.create_secret(
        Name=name,
        SecretString="original-value",
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))
    original_version = create_resp["VersionId"]

    code, message = _error_code(
        lambda: sm.put_secret_value(SecretId=name, SecretString="x", SecretBinary=b"y")
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "You can't specify both a binary secret value and a string secret value in the same secret.", f"unexpected refusal message: {message!r}"

    # Effect absent: no new version was created, AWSCURRENT still points at the original value.
    desc = sm.describe_secret(SecretId=name)
    assert list(desc["VersionIdsToStages"].keys()) == [original_version], (
        "a rejected PutSecretValue still created a new secret version"
    )
    got = sm.get_secret_value(SecretId=name)
    assert got["SecretString"] == "original-value"
    assert got["VersionId"] == original_version

    # Positive control in the same file: a well-formed call (string only) succeeds normally.
    put_resp = sm.put_secret_value(SecretId=name, SecretString="second-value")
    got2 = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
    assert got2["SecretString"] == "second-value"
    assert got2["VersionId"] == put_resp["VersionId"]
    assert got2["VersionId"] != original_version


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
