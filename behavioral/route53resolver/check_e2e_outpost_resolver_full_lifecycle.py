"""e2e-outpost-resolver-full-lifecycle."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-outpost-resolver-full-lifecycle"
GROUP = "e2e"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With a racked Outpost, an OutpostResolver goes OPERATIONAL, updates InstanceCount and is gone
    after delete; without one, CreateOutpostResolver is refused with a ValidationException naming
    the Outpost and leaves nothing behind.
    """
    outposts = ctx.client("outposts")
    r53r = ctx.client("route53resolver")

    available = outposts.list_outposts().get("Outposts", [])
    if available:
        _run_full_lifecycle(ctx, r53r, available[0]["OutpostArn"])
        return

    _assert_creation_refused_without_a_racked_outpost(ctx, r53r)


def _run_full_lifecycle(ctx, r53r, outpost_arn: str) -> None:
    resolver = r53r.create_outpost_resolver(
        CreatorRequestId=ctx.unique_name("sim2real-outres-req-"),
        Name=ctx.unique_name("sim2real-outres-")[:255],
        PreferredInstanceType="m5.large",
        OutpostArn=outpost_arn,
        InstanceCount=2,
        Tags=[{"Key": "env", "Value": "behavioral-test"}],
    )["OutpostResolver"]
    resolver_id = resolver["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: r53r.delete_outpost_resolver(Id=resolver_id)))

    status = _poll_until(
        lambda: r53r.get_outpost_resolver(Id=resolver_id)["OutpostResolver"]["Status"],
        lambda s: s in ("OPERATIONAL", "ACTION_NEEDED", "FAILED_CREATION"),
        timeout_s=900,
        interval_s=15,
        what="OutpostResolver create to reach a terminal status",
    )
    assert status == "OPERATIONAL", f"expected OPERATIONAL after create, got {status!r}"

    listed = r53r.list_outpost_resolvers(OutpostArn=outpost_arn)["OutpostResolvers"]
    assert any(o["Id"] == resolver_id for o in listed), (
        f"resolver {resolver_id} not present in ListOutpostResolvers for {outpost_arn}"
    )

    updated = r53r.update_outpost_resolver(Id=resolver_id, InstanceCount=3)["OutpostResolver"]
    assert updated["InstanceCount"] == 3, (
        f"expected InstanceCount 3 immediately after update, got {updated['InstanceCount']!r}"
    )

    status = _poll_until(
        lambda: r53r.get_outpost_resolver(Id=resolver_id)["OutpostResolver"]["Status"],
        lambda s: s in ("OPERATIONAL", "ACTION_NEEDED", "FAILED_CREATION"),
        timeout_s=900,
        interval_s=15,
        what="OutpostResolver update to reach a terminal status",
    )
    assert status == "OPERATIONAL", f"expected OPERATIONAL after update, got {status!r}"
    final_count = r53r.get_outpost_resolver(Id=resolver_id)["OutpostResolver"]["InstanceCount"]
    assert final_count == 3, f"expected InstanceCount 3 to have settled, got {final_count!r}"

    r53r.delete_outpost_resolver(Id=resolver_id)
    deleted_code = _wait_refused(
        lambda: r53r.get_outpost_resolver(Id=resolver_id),
        timeout_s=300,
        interval_s=10,
        what="deleted OutpostResolver to become not-found",
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {deleted_code!r}"
    )

    remaining = r53r.list_outpost_resolvers(OutpostArn=outpost_arn)["OutpostResolvers"]
    assert all(o["Id"] != resolver_id for o in remaining), (
        f"deleted resolver {resolver_id} still present in ListOutpostResolvers"
    )


def _assert_creation_refused_without_a_racked_outpost(ctx, r53r) -> None:
    r53r.list_outpost_resolvers()

    account_id = ctx.account
    op_suffix = "".join(random.choices("0123456789abcdef", k=17))
    unracked_outpost_arn = f"arn:aws:outposts:{ctx.region}:{account_id}:outpost/op-{op_suffix}"
    name = ctx.unique_name("sim2real-outres-")[:255]

    # InstanceCount=4 is the documented minimum: it must be in-range so this call fails on
    # the (non-racked) OutpostArn, not on an unrelated instance-count validation error.
    code, message = _client_error(
        lambda: r53r.create_outpost_resolver(
            CreatorRequestId=ctx.unique_name("sim2real-outres-req-"),
            Name=name,
            PreferredInstanceType="m5.large",
            OutpostArn=unracked_outpost_arn,
            InstanceCount=4,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a non-racked OutpostArn, got {code!r} ({message!r})"
    )
    expected_message = f'[RSLVR-03007] Cannot find the Outpost with Arn "{unracked_outpost_arn}".'
    assert message == expected_message, (
        f"expected the refusal to name the Outpost: {expected_message!r}, got {message!r}"
    )

    # Effect absent: no resolver was left behind under the rejected name.
    remaining_names = {r["Name"] for r in r53r.list_outpost_resolvers().get("OutpostResolvers", [])}
    assert name not in remaining_names, f"an OutpostResolver named {name!r} leaked from a rejected create call"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


def _wait_refused(fn, *, timeout_s: float, interval_s: float, what: str):
    """Retry fn() until AWS refuses it; return its error code; raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}")
        time.sleep(interval_s)


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
