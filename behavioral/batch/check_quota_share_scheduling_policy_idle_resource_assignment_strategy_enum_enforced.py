"""quota-share-scheduling-policy-idle-resource-assignment-strategy-enum-enforced."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quota-share-scheduling-policy-idle-resource-assignment-strategy-enum-enforced"
GROUP = "scheduling-policy"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
# The only member of the QuotaShareIdleResourceAssignmentStrategy enum, identical in every account.
_ONLY_STRATEGY = "FIFO"
_INVALID_STRATEGY = "STRICT"


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step only)."""
    fn()


def _client_error(fn):
    """Call fn(); return its botocore Error dict with the RequestId added; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return dict(exc.response.get("Error", {}), RequestId=exc.response.get("ResponseMetadata", {}).get("RequestId"))
    raise AssertionError(
        f"real AWS refuses an idleResourceAssignmentStrategy outside the modelled enum, but the "
        f"call SUCCEEDED and returned {result!r}"
    )


def _create_policy(ctx, bat, *, strategy):
    """CreateSchedulingPolicy with a quotaSharePolicy. Returns (name, arn). Raises on refusal."""
    name = ctx.unique_name("sim2real-behav-sp-qs-")
    arn = bat.create_scheduling_policy(
        name=name,
        quotaSharePolicy={"idleResourceAssignmentStrategy": strategy},
        tags=dict(_MANAGED_TAGS),
    )["arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_scheduling_policy(arn=arn)))
    return name, arn


def _policy_arns(bat):
    """Every scheduling-policy ARN in this account/region, paginated."""
    out = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = bat.list_scheduling_policies(**kwargs)
        out.extend(p["arn"] for p in page.get("schedulingPolicies", []))
        token = page.get("nextToken")
        if not token:
            return out


def _describe_policy(bat, arn):
    policies = bat.describe_scheduling_policies(arns=[arn])["schedulingPolicies"]
    assert len(policies) == 1, (
        f"DescribeSchedulingPolicies(arns=[{arn!r}]) must return exactly 1 policy, got "
        f"{len(policies)}: {policies!r}"
    )
    return policies[0]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A quota-share scheduling policy accepts FIFO, the one member of its strategy enum, and
    refuses anything else with ClientException, creating no policy for the refused call.

    Reference: https://docs.aws.amazon.com/batch/latest/APIReference/API_QuotaSharePolicy.html
    """
    bat = ctx.client("batch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; refusing to run against an unidentified target"

    good_name, good_arn = _create_policy(ctx, bat, strategy=_ONLY_STRATEGY)
    assert good_arn.startswith("arn:"), (
        f"CreateSchedulingPolicy must return a scheduling-policy ARN, got {good_arn!r}"
    )
    assert good_arn.endswith(f"/{good_name}"), (
        f"the returned ARN must end in the name it was given; name={good_name!r} arn={good_arn!r}"
    )

    detail = _describe_policy(bat, good_arn)
    assert detail["name"] == good_name, (
        f"DescribeSchedulingPolicies must report the name the policy was created with; expected "
        f"{good_name!r}, got {detail.get('name')!r}"
    )
    stored = detail["quotaSharePolicy"]
    assert stored["idleResourceAssignmentStrategy"] == _ONLY_STRATEGY, (
        f"the quota-share strategy must round-trip as {_ONLY_STRATEGY!r}, "
        f"DescribeSchedulingPolicies reports {stored.get('idleResourceAssignmentStrategy')!r}"
    )
    assert "fairsharePolicy" not in detail, (
        f"only one of fairsharePolicy and quotaSharePolicy may be set, so a quota-share policy "
        f"must report NO fairsharePolicy; it reports {detail.get('fairsharePolicy')!r}"
    )
    assert good_arn in _policy_arns(bat), (
        f"the accepted policy {good_arn!r} must be listed by ListSchedulingPolicies, which is the "
        f"same read the negative below uses to prove absence"
    )

    bad_name = ctx.unique_name("sim2real-behav-sp-qs-bad-")
    err = _client_error(
        lambda: bat.create_scheduling_policy(
            name=bad_name,
            quotaSharePolicy={"idleResourceAssignmentStrategy": _INVALID_STRATEGY},
            tags=dict(_MANAGED_TAGS),
        )
    )

    assert err.get("Code") == "ClientException", (
        f"idleResourceAssignmentStrategy={_INVALID_STRATEGY!r} must be refused with "
        f"ClientException, got Code={err.get('Code')!r} Message={err.get('Message')!r}"
    )
    message = err.get("Message")
    expected = (
        f"Error executing request, Exception : Idle resource assignment strategy must be one of "
        f"[{_ONLY_STRATEGY}]., RequestId: {err.get('RequestId')}"
    )
    assert message == expected, (
        f"the refusal must name the closed set it enforced, so a generic 400 or an authorization "
        f"failure cannot pass for this validation; expected {expected!r}, got {message!r}"
    )
    arns = _policy_arns(bat)
    leaked = [a for a in arns if a.endswith(f"/{bad_name}")]
    assert not leaked, (
        f"a refused CreateSchedulingPolicy must create nothing, but ListSchedulingPolicies "
        f"returned {leaked} for the refused name {bad_name!r}"
    )

    # Three consecutive reads, so a single lucky poll is not the evidence.
    for i in range(3):
        again = _describe_policy(bat, good_arn)
        assert again["quotaSharePolicy"]["idleResourceAssignmentStrategy"] == _ONLY_STRATEGY, (
            f"read {i + 1} of 3: the refused call must not have altered the accepted policy "
            f"{good_arn!r}; its strategy now reads "
            f"{again['quotaSharePolicy'].get('idleResourceAssignmentStrategy')!r}"
        )
        assert "fairsharePolicy" not in again, (
            f"read {i + 1} of 3: the accepted policy grew a fairsharePolicy "
            f"({again.get('fairsharePolicy')!r}) after the refused call"
        )
        time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
