"""put-secret-value-missing-value-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "put-secret-value-missing-value-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSecretValue with neither SecretString nor SecretBinary must fail, must not create a new
    version, and a well-formed PutSecretValue on the same secret must still succeed afterward -
    otherwise this could not tell "rejects a missing value" from "rejects every PutSecretValue"."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    create_resp = _create_secret(
        sm, ctx, name=name, secret_string="v1",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    original_version = create_resp["VersionId"]

    code, message = _error_code(lambda: sm.put_secret_value(SecretId=name))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException, got {code!r}"
    )
    assert message == "You must provide either SecretString or SecretBinary.", f"unexpected refusal message: {message!r}"

    # Effect absent: the rejected call created no new version.
    desc = sm.describe_secret(SecretId=name)
    assert list(desc["VersionIdsToStages"].keys()) == [original_version], (
        f"a rejected PutSecretValue with no value still created a version: {desc['VersionIdsToStages']!r}"
    )
    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "v1", f"expected unchanged SecretString 'v1', got {val['SecretString']!r}"
    assert val["VersionId"] == original_version, (
        f"expected unchanged VersionId {original_version!r}, got {val['VersionId']!r}"
    )

    # Positive control: a well-formed PutSecretValue on the same secret still succeeds.
    put_resp = sm.put_secret_value(SecretId=name, SecretString="v2")
    got2 = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
    assert got2["SecretString"] == "v2", f"expected 'v2', got {got2['SecretString']!r}"
    assert got2["VersionId"] == put_resp["VersionId"], (
        f"expected VersionId {put_resp['VersionId']!r}, got {got2['VersionId']!r}"
    )
    assert got2["VersionId"] != original_version


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
