"""configuration-revisions-append-only-immutable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-revisions-append-only-immutable"
GROUP = 'configuration'
SERVICES = ['kafka']


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    A call that succeeds raises AssertionError: the refusal is the claim.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _paginate(fn, list_key, **kwargs):
    items, token = [], None
    for _ in range(200):
        page_kwargs = dict(kwargs)
        if token:
            page_kwargs["NextToken"] = token
        resp = fn(**page_kwargs)
        items.extend(resp.get(list_key, []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


def _delete_configuration_if_present(msk, arn):
    """Teardown: delete the configuration unless the check already deleted it."""
    try:
        msk.delete_configuration(Arn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Message") != "Configuration ARN does not exist.":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Configuration revisions are service-numbered (1, then 2) with immutable ServerProperties,
    an unissued revision is BadRequestException, and DeleteConfiguration passes through DELETING."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-config-append-")

    created = msk.create_configuration(
        Name=name,
        ServerProperties=b"auto.create.topics.enable=false",
        KafkaVersions=["3.6.0"],
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda _a=arn: _delete_configuration_if_present(msk, _a))
    assert created["State"] == "ACTIVE", created
    assert created["LatestRevision"]["Revision"] == 1, created

    desc = msk.describe_configuration(Arn=arn)
    assert desc["State"] == "ACTIVE", desc
    assert desc["LatestRevision"]["Revision"] == 1, desc

    upd = msk.update_configuration(
        Arn=arn, ServerProperties=b"auto.create.topics.enable=true\nnum.partitions=2"
    )
    assert upd["LatestRevision"]["Revision"] == 2, upd["LatestRevision"]

    revisions = {
        r["Revision"]
        for r in _paginate(msk.list_configuration_revisions, "Revisions", Arn=arn)
    }
    assert {1, 2}.issubset(revisions), revisions

    rev1 = msk.describe_configuration_revision(Arn=arn, Revision=1)
    rev2 = msk.describe_configuration_revision(Arn=arn, Revision=2)
    assert rev1["ServerProperties"] == b"auto.create.topics.enable=false", rev1
    assert rev2["ServerProperties"] == b"auto.create.topics.enable=true\nnum.partitions=2", rev2

    ghost_rev = _err(lambda: msk.describe_configuration_revision(Arn=arn, Revision=99))
    assert ghost_rev[0] == "BadRequestException", f"expected BadRequestException, got {ghost_rev!r}"
    assert ghost_rev[1] == "Configuration ARN does not exist.", ghost_rev

    names = [c["Name"] for c in _paginate(msk.list_configurations, "Configurations")]
    assert name in names, name

    deleted = msk.delete_configuration(Arn=arn)
    assert deleted["Arn"] == arn, deleted
    assert deleted["State"] == "DELETING", deleted.get("State")

    def _describe_after_delete():
        try:
            return ("state", msk.describe_configuration(Arn=arn)["State"], None)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return ("error", err.get("Code"), err.get("Message"))

    outcome = _poll_until(
        _describe_after_delete,
        lambda o: o != ("state", "DELETING", None),
        description="deleted configuration to stop reporting DELETING on an independent read",
    )
    assert outcome == ("error", "BadRequestException", "Configuration ARN does not exist."), (
        f"expected DescribeConfiguration on a deleted configuration to answer "
        f"BadRequestException, got {outcome}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
