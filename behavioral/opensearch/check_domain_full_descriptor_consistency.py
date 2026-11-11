"""domain-full-descriptor-consistency."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-full-descriptor-consistency"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """All domain-scoped describe endpoints (config, change-progress, health, nodes,
    bulk describe, name listing) report mutually consistent state across the
    create-to-delete lifecycle."""
    aos = ctx.client("opensearch")
    name = _create_minimal_domain(ctx)

    names_after_create = {d["DomainName"] for d in aos.list_domain_names().get("DomainNames", [])}
    assert name in names_after_create, "domain missing from ListDomainNames right after creation"

    status = _wait_domain_active(ctx, name, timeout_s=2400.0)
    domain_id = status["DomainId"]
    arn = status["ARN"]

    describe = aos.describe_domain(DomainName=name)["DomainStatus"]
    assert describe["DomainId"] == domain_id, f"DomainId drifted: {describe['DomainId']!r} != {domain_id!r}"
    assert describe["ARN"] == arn, f"ARN drifted: {describe['ARN']!r} != {arn!r}"
    assert describe["Created"] is True, f"expected Created=True once Active, got {describe['Created']!r}"
    assert describe["Processing"] is False, f"expected Processing=False once Active, got {describe['Processing']!r}"

    config = aos.describe_domain_config(DomainName=name)["DomainConfig"]
    assert config["EngineVersion"]["Options"] == describe["EngineVersion"], (
        f"DescribeDomainConfig EngineVersion {config['EngineVersion']['Options']!r} != "
        f"DescribeDomain EngineVersion {describe['EngineVersion']!r}"
    )
    assert config["ClusterConfig"]["Options"]["InstanceType"] == describe["ClusterConfig"]["InstanceType"], (
        f"DescribeDomainConfig InstanceType {config['ClusterConfig']['Options']['InstanceType']!r} != "
        f"DescribeDomain InstanceType {describe['ClusterConfig']['InstanceType']!r}"
    )

    change_progress = _poll_until(
        lambda: aos.describe_domain_change_progress(DomainName=name)["ChangeProgressStatus"],
        lambda c: c.get("Status") not in ("PENDING", "PROCESSING"),
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert change_progress["Status"] == "COMPLETED", f"expected the create change to end COMPLETED: {change_progress}"

    health = _poll_until(
        lambda: aos.describe_domain_health(DomainName=name),
        lambda h: h.get("ClusterHealth") in ("Green", "Yellow", "Red"),
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert health["DomainState"] == "Active", f"expected DomainState=Active, got {health['DomainState']!r}"

    configured_instance_count = config["ClusterConfig"]["Options"]["InstanceCount"]
    nodes = aos.describe_domain_nodes(DomainName=name)["DomainNodesStatusList"]
    assert len(nodes) == configured_instance_count, (
        f"DescribeDomainNodes reported {len(nodes)} node(s), "
        f"but DescribeDomainConfig's ClusterConfig.InstanceCount is {configured_instance_count!r}"
    )
    assert all("NodeId" in n for n in nodes), f"a node is missing NodeId: {nodes!r}"

    bulk = aos.describe_domains(DomainNames=[name])["DomainStatusList"]
    assert len(bulk) == 1, f"expected exactly 1 domain in DescribeDomains bulk result, got {len(bulk)}"
    assert bulk[0]["DomainId"] == domain_id, f"bulk DomainId {bulk[0]['DomainId']!r} != {domain_id!r}"
    assert bulk[0]["ARN"] == arn, f"bulk ARN {bulk[0]['ARN']!r} != {arn!r}"

    aos.delete_domain(DomainName=name)

    def _domain_terminal():
        try:
            d = aos.describe_domain(DomainName=name)["DomainStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        return bool(d.get("Deleted"))

    _poll_until(lambda: _domain_terminal(), lambda v: v, timeout_s=_budget_s(ctx, 180.0), interval_s=2.0, ctx=ctx)

    # ListDomainNames is eventually consistent and keeps listing a deleted domain for a while.
    def _name_gone():
        names = {d["DomainName"] for d in aos.list_domain_names().get("DomainNames", [])}
        return name not in names

    # The lag behind DescribeDomain's ResourceNotFoundException can exceed 480s (up to ~840s
    # seen), so the bound is 900s.
    assert _poll_until(_name_gone, lambda gone: gone, timeout_s=_budget_s(ctx, 900.0), interval_s=2.0, ctx=ctx), (
        "domain still listed in ListDomainNames after deletion"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"condition (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_minimal_domain(ctx, engine_version=None):
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-osb2-")
    account_id = sts.get_caller_identity()["Account"]
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*",
        }],
    })
    kwargs = dict(
        DomainName=name,
        # Pinned: the default (latest) engine version provisions noticeably slower, which can
        # push the full lifecycle past the check's time budget.
        EngineVersion=engine_version or "OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=policy,
        TagList=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    aos.create_domain(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name



def _safe_delete_domain(ctx, name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_domain(DomainName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s=2400.0):
    aos = ctx.client("opensearch")

    def probe():
        return aos.describe_domain(DomainName=name)["DomainStatus"]

    def done(s):
        return bool(s.get("Created")) and not s.get("Processing")

    return _poll_until(probe, done, timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0, ctx=ctx)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
