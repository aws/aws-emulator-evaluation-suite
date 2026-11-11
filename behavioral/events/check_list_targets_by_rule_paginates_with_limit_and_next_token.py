"""list-targets-by-rule-paginates-with-limit-and-next-token."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-targets-by-rule-paginates-with-limit-and-next-token"
GROUP = 'targets'
SERVICES = ['events']


def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _queue_arn(ev, ctx, suffix: str) -> str:
    """A syntactically valid SQS queue ARN in this account and region (EventBridge does not
    require a target to exist at PutTargets time)."""
    partition = ev.describe_event_bus(Name="default")["Arn"].split(":")[1]
    return f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:sim2real-behav-{suffix}"


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTargetsByRule pages five targets with Limit=2 as 2/2/1, each keeping its Arn and Input,
    the last page has no NextToken, an unpaged call returns all five, and a forged NextToken is
    refused.
    """
    ev = ctx.client("events")
    rule = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(
        Name=rule,
        EventPattern=json.dumps({"source": ["sim2real.pagination"]}),
        State="DISABLED",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))

    ids = [f"target-{i}" for i in range(5)]
    targets = [
        {"Id": tid, "Arn": _queue_arn(ev, ctx, f"page-{i}"), "Input": json.dumps({"n": i})}
        for i, tid in enumerate(ids)
    ]
    resp = ev.put_targets(Rule=rule, Targets=targets)
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=ids))
    assert resp["FailedEntryCount"] == 0, f"PutTargets of five targets reported failures: {resp!r}"

    whole = ev.list_targets_by_rule(Rule=rule)
    assert sorted(t["Id"] for t in whole["Targets"]) == ids, (
        f"an unpaged ListTargetsByRule returned Ids {sorted(t['Id'] for t in whole['Targets'])!r}, "
        f"expected {ids!r}"
    )
    assert "NextToken" not in whole, (
        f"an unpaged ListTargetsByRule holding all five targets carried NextToken "
        f"{whole.get('NextToken')!r}"
    )

    page_sizes: list[int] = []
    seen: list[dict] = []
    token = None
    for _ in range(10):
        kwargs = {"Rule": rule, "Limit": 2}
        if token:
            kwargs["NextToken"] = token
        page = ev.list_targets_by_rule(**kwargs)
        page_sizes.append(len(page["Targets"]))
        seen.extend(page["Targets"])
        token = page.get("NextToken")
        if not token:
            break
    assert token is None, f"ListTargetsByRule with Limit=2 was still paging after 10 pages: {page_sizes!r}"
    assert page_sizes == [2, 2, 1], f"Limit=2 over five targets gave page sizes {page_sizes!r}, expected [2, 2, 1]"
    seen_ids = [t["Id"] for t in seen]
    assert sorted(seen_ids) == ids, (
        f"the pages held Ids {seen_ids!r}: expected each of {ids!r} exactly once"
    )
    by_id = {t["Id"]: t for t in seen}
    for i, tid in enumerate(ids):
        assert by_id[tid]["Arn"] == targets[i]["Arn"], (
            f"target {tid!r} came back on its page with Arn {by_id[tid]['Arn']!r}, "
            f"expected {targets[i]['Arn']!r}"
        )
        assert json.loads(by_id[tid]["Input"]) == {"n": i}, (
            f"target {tid!r} came back on its page with Input {by_id[tid].get('Input')!r}, expected n={i}"
        )

    code, message = _error(
        lambda: ev.list_targets_by_rule(Rule=rule, Limit=2, NextToken="sim2real-not-a-token")
    )
    assert code == "ValidationException", f"a NextToken the service never issued gave {code!r}"
    assert message == "Parameter NextToken is not valid.", (
        f"a NextToken the service never issued was refused with message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
