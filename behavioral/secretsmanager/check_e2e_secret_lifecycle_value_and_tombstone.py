"""e2e-secret-lifecycle-value-and-tombstone."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-secret-lifecycle-value-and-tombstone"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

_SUCCEEDED = "<call succeeded>"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """create->put-value->tag->delete(recovery)->restore->force-delete: value survives restore, vanishes after force-delete (read not-found, absent from ListSecrets,
    PutSecretValue not-found)."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-lifecycle-secret-")

    created = sm.create_secret(Name=name, SecretString="v1-initial", Tags=[{"Key": "sim2real", "Value": CHECK}])
    arn = created["ARN"]

    def _cleanup():
        try:
            sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    sm.put_secret_value(SecretId=arn, SecretString="v2-updated")
    current = sm.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"]
    previous = sm.get_secret_value(SecretId=arn, VersionStage="AWSPREVIOUS")["SecretString"]
    assert (current, previous) == ("v2-updated", "v1-initial"), (
        f"after PutSecretValue AWSCURRENT/AWSPREVIOUS read {current!r}/{previous!r}, "
        f"expected 'v2-updated'/'v1-initial'"
    )
    sm.tag_resource(SecretId=arn, Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}])

    described = sm.describe_secret(SecretId=arn)
    assert {"Key": "sim2real-owner", "Value": "behavioral-check"} in described["Tags"], (
        f"expected sim2real-owner tag in {described['Tags']!r}"
    )

    sm.delete_secret(SecretId=arn, RecoveryWindowInDays=7)
    described = _poll_until(
        lambda: sm.describe_secret(SecretId=arn),
        lambda d: d.get("DeletedDate") is not None,
        timeout_s=30.0,
    )
    assert described["DeletedDate"] is not None, (
        f"expected DeletedDate set after scheduled delete, got {described!r}"
    )

    sm.restore_secret(SecretId=arn)
    described = _poll_until(
        lambda: sm.describe_secret(SecretId=arn),
        lambda d: d.get("DeletedDate") is None,
        timeout_s=30.0,
    )
    assert described.get("DeletedDate") is None, (
        f"expected DeletedDate cleared after restore, got {described!r}"
    )

    # Restoring must preserve the latest secret content, not roll it back.
    value = sm.get_secret_value(SecretId=arn)
    assert value["SecretString"] == "v2-updated", (
        f"expected restore to preserve latest value 'v2-updated', got {value['SecretString']!r}"
    )

    sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)

    # Force delete completes asynchronously: poll the read to its terminal not-found.
    read_resp = _poll_until(
        lambda: _try(lambda: sm.get_secret_value(SecretId=arn)),
        lambda r: r["Error"]["Code"] == "ResourceNotFoundException",
        timeout_s=30.0,
    )
    _assert_not_found(read_resp, "GetSecretValue post-force-delete")

    # Gone beat 2: the listing filtered to the name no longer contains this ARN.
    _poll_until(
        lambda: [s["ARN"] for s in _list_secrets(sm, name)],
        lambda arns: arn not in arns,
        timeout_s=60.0,
    )

    # A mutation on the now-permanently-deleted id must also fail, not just a read.
    mutation_resp = _error(
        lambda: sm.put_secret_value(SecretId=arn, SecretString="v3-after-force-delete")
    )
    _assert_not_found(mutation_resp, "PutSecretValue post-force-delete")


def _error(fn):
    """Call fn(), which must fail; return its error response (Error + ResponseMetadata). An
    unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _try(fn):
    """A poll probe: the error response of fn(), or a Code no service returns on success."""
    try:
        result = fn()
    except ClientError as err:
        return err.response
    return {"Error": {"Code": _SUCCEEDED, "Message": repr(result)}}


def _assert_not_found(response, what):
    """The response is Secrets Manager's not-found: exact code and message, HTTP 4xx."""
    got = (response["Error"]["Code"], response["Error"].get("Message"))
    expected = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
    assert got == expected, f"{what}: expected {expected}, got {got!r}"
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: expected HTTP 4xx, got {status!r}"


def _list_secrets(sm, name):
    out = []
    for page in sm.get_paginator("list_secrets").paginate(
            Filters=[{"Key": "name", "Values": [name]}]):
        out.extend(page.get("SecretList", []))
    return out


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
