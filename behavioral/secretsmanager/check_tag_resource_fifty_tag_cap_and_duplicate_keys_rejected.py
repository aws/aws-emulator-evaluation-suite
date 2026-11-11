"""tag-resource-fifty-tag-cap-and-duplicate-keys-rejected."""
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
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises."""
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


CHECK = "tag-resource-fifty-tag-cap-and-duplicate-keys-rejected"
GROUP = "tagging"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A secret holds at most 50 tags: filling to 50 succeeds, a 51st new key is refused leaving the
    50 untouched, overwriting a key at the cap is accepted, and CreateSecret refuses 51 tags or a
    repeated key without creating the secret."""
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-tagcap-")
    name = f"{base}-capped"
    _create_secret(sm, ctx, name, SecretString="sim2real-not-a-real-secret")

    # One tag (sim2real) came with the create; 49 more reach the cap of 50.
    sm.tag_resource(SecretId=name, Tags=[{"Key": f"k{i:02d}", "Value": "v"} for i in range(49)])

    def tag_map():
        return {t["Key"]: t["Value"] for t in sm.describe_secret(SecretId=name).get("Tags", [])}

    assert len(tag_map()) == 50, f"the secret must hold 50 tags, holds {len(tag_map())}"

    code, message = _refusal(
        lambda: sm.tag_resource(SecretId=name, Tags=[{"Key": "k-extra", "Value": "v"}]))
    assert code == "InvalidRequestException", f"a 51st tag must be refused, got {code!r}"
    assert message == "The request included too many tags.", f"unexpected 51st-tag message: {message!r}"
    after = tag_map()
    assert len(after) == 50 and "k-extra" not in after, (
        f"the refused tag must not be applied; secret holds {len(after)} tags"
    )

    sm.tag_resource(SecretId=name, Tags=[{"Key": "k00", "Value": "overwritten"}])
    upserted = tag_map()
    assert (len(upserted), upserted.get("k00")) == (50, "overwritten"), (
        f"overwriting an existing key at the cap must be accepted; got {len(upserted)} tags, "
        f"k00={upserted.get('k00')!r}"
    )

    too_many = f"{base}-toomany"
    ctx.on_cleanup(lambda: _reap_secret(sm, too_many))
    code, message = _refusal(lambda: sm.create_secret(
        Name=too_many, SecretString="x", Tags=[{"Key": f"k{i:02d}", "Value": "v"} for i in range(51)]))
    assert code == "InvalidRequestException", f"CreateSecret with 51 tags must be refused, got {code!r}"
    assert message == "The request included too many tags.", f"unexpected 51-tag create message: {message!r}"

    dup = f"{base}-dupkey"
    ctx.on_cleanup(lambda: _reap_secret(sm, dup))
    code, message = _refusal(lambda: sm.create_secret(
        Name=dup, SecretString="x", Tags=[{"Key": "env", "Value": "a"}, {"Key": "env", "Value": "b"}]))
    assert code == "InvalidParameterException", f"a repeated tag key must be refused, got {code!r}"
    assert message == "Duplicate tag keys in request", f"unexpected duplicate-key message: {message!r}"

    for refused in (too_many, dup):
        code, _ = _refusal(lambda refused=refused: sm.describe_secret(SecretId=refused))
        assert code == "ResourceNotFoundException", (
            f"a refused CreateSecret must not create the secret, DescribeSecret gave {code!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
