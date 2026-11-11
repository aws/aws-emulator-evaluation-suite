"""batch-get-secret-value-duplicate-or-more-than-twenty-ids-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, extra_tags=(), **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}, *extra_tags], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _refusal(fn):
    """Call fn() and return the (Error.Code, Error.Message) it raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=150.0, interval_s=3.0):
    """Bounded poll; returns the last observation whether or not the predicate held."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


CHECK = "batch-get-secret-value-duplicate-or-more-than-twenty-ids-rejected"
GROUP = "data-plane"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetSecretValue fails the whole call for a duplicate id, more than 20 ids, or neither
    SecretIdList nor Filters; exactly 20 distinct ids is served, unknown ids as per-entry Errors."""
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-bgbad-")
    name = f"{base}-real"
    created = _create_secret(sm, ctx, name, SecretString="sim2real-not-a-real-secret")

    code, message = _refusal(lambda: sm.batch_get_secret_value(SecretIdList=[name, name]))
    assert code == "InvalidRequestException", f"a duplicate id must be refused, got {code!r}"
    assert message == (
        f"Duplicate secret ID encountered: {name}. You cannot enter duplicate secrets in the "
        "secret ID list."
    ), f"unexpected duplicate-id message: {message!r}"

    missing = [f"{base}-absent-{i:02d}" for i in range(20)]
    code, message = _refusal(lambda: sm.batch_get_secret_value(SecretIdList=[name, *missing]))
    assert code == "InvalidParameterException", f"21 ids must be refused, got {code!r}"
    assert message == "The secret ID list has too many IDs. You can include up to 20 secret IDs.", (
        f"unexpected too-many-ids message: {message!r}"
    )

    code, message = _refusal(lambda: sm.batch_get_secret_value())
    assert code == "InvalidParameterException", f"an empty request must be refused, got {code!r}"
    assert message == "You must specify a list of Secret IDs or a filter value.", (
        f"unexpected empty-request message: {message!r}"
    )

    # Positive control at the boundary: 20 distinct ids, one real.
    ok = sm.batch_get_secret_value(SecretIdList=[name, *missing[:19]])
    served = [(e["Name"], e["VersionId"]) for e in ok["SecretValues"]]
    assert served == [(name, created["VersionId"])], (
        f"exactly the one real secret must be served, got {len(served)} entries"
    )
    errors = sorted((e["SecretId"], e["ErrorCode"]) for e in ok.get("Errors", []))
    assert errors == [(m, "ResourceNotFoundException") for m in missing[:19]], (
        f"each unknown id must be a per-secret ResourceNotFoundException, got {len(errors)} errors"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
