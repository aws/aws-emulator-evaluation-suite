"""last-changed-date-advances-on-tag-put-and-update-but-not-on-reads."""
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


CHECK = "last-changed-date-advances-on-tag-put-and-update-but-not-on-reads"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """LastChangedDate moves strictly forward on TagResource, PutSecretValue and UpdateSecret and
    stays put across GetSecretValue, DescribeSecret and ListSecretVersionIds; drift reports key
    on it. Only an ordering is asserted, never an elapsed time."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-lastchg-")
    _create_secret(sm, ctx, name, SecretString="v1")

    def changed():
        return sm.describe_secret(SecretId=name)["LastChangedDate"]

    t0 = changed()
    sm.get_secret_value(SecretId=name)
    sm.list_secret_version_ids(SecretId=name)
    sm.describe_secret(SecretId=name)
    # DescribeSecret is eventually consistent, so each observation is a bounded poll to
    # convergence; a read that moved the stamp would never converge back to it.
    settled = _poll(changed, lambda t: t == t0, timeout_s=30.0, interval_s=2.0)
    assert settled == t0, (
        f"reads must not change LastChangedDate: {t0.isoformat()} -> {settled.isoformat()}"
    )

    steps = [
        ("TagResource", lambda: sm.tag_resource(SecretId=name, Tags=[{"Key": "owner", "Value": "team-a"}])),
        ("PutSecretValue", lambda: sm.put_secret_value(SecretId=name, SecretString="v2")),
        ("UpdateSecret(Description)", lambda: sm.update_secret(SecretId=name, Description="rotated by hand")),
    ]
    previous = t0
    for label, mutate in steps:
        mutate()
        now = _poll(changed, lambda t, previous=previous: t > previous, timeout_s=60.0, interval_s=2.0)
        assert now > previous, (
            f"{label} must advance LastChangedDate: {previous.isoformat()} -> {now.isoformat()}"
        )
        sm.get_secret_value(SecretId=name)
        after_read = _poll(changed, lambda t, now=now: t == now, timeout_s=30.0, interval_s=2.0)
        assert after_read == now, (
            f"a read after {label} must not move LastChangedDate: {now.isoformat()} -> "
            f"{after_read.isoformat()}"
        )
        previous = now

    final = sm.describe_secret(SecretId=name)
    assert final.get("Description") == "rotated by hand", "the description update must be visible"
    assert {t["Key"]: t["Value"] for t in final.get("Tags", [])}.get("owner") == "team-a", (
        "the tag must be visible"
    )
    assert sm.get_secret_value(SecretId=name)["SecretString"] == "v2", "the put value must be current"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
