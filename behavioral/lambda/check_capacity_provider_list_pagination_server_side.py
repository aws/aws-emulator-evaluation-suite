"""capacity-provider-list-pagination-server-side."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-list-pagination-server-side"
GROUP = "server-side"
SERVICES = ["lambda"]

_NUM_PROVIDERS = 3


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCapacityProviders pagination tokens are managed server-side: paging with a small
    MaxItems returns non-overlapping pages that, taken together, cover every capacity
    provider exactly once."""
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")

    try:
        subnet_ids, sg_id = _default_network(ec2, ctx=ctx)
        role_arn = _create_operator_role(ctx, iam)
        name_to_arn = _create_capacity_providers(ctx, lam, subnet_ids, sg_id, role_arn, _NUM_PROVIDERS)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 - environment/prerequisite failure
        raise AssertionError(f"unreachable: could not provision capacity providers: {exc}") from exc

    # CapacityProvider (the shape returned by Get/List, and embedded in Create's response) has no
    # CapacityProviderName/Name field at all -- only CapacityProviderArn identifies it. Identity
    # here must be the ARN; the human-chosen name is kept only for CapacityProviderName-addressed
    # calls (Get/Delete) and for readable failure messages.
    created_arns = list(name_to_arn.values())
    arn_to_name = {arn: name for name, arn in name_to_arn.items()}

    _last_locate_stats: dict[str, object] = {}

    def _sweep(max_items, start_marker=None, stop_when=None, max_pages=2000):
        """Page ListCapacityProviders starting at start_marker with the given page size.

        Returns (arns, page_sizes, pages) where pages is a list of (begin_marker,
        arns_in_that_page).
        """
        arns: list[str] = []
        page_sizes: list[int] = []
        pages: list[tuple[object, list[str]]] = []
        marker = start_marker
        # Bounded on round-trip *count* purely as a safety net against a genuine "server never
        # terminates the page chain" bug, and to keep a single attempt cheap.
        for _ in range(max_pages):
            begin_marker = marker
            kwargs = {"MaxItems": max_items}
            if marker:
                kwargs["Marker"] = marker
            resp = lam.list_capacity_providers(**kwargs)
            items = resp.get("CapacityProviders", [])
            page_sizes.append(len(items))
            page_arns: list[str] = []
            for item in items:
                arn = item.get("CapacityProviderArn")
                if arn:
                    arns.append(arn)
                    page_arns.append(arn)
            pages.append((begin_marker, page_arns))
            marker = resp.get("NextMarker")
            if not marker:
                break
            if stop_when is not None and stop_when(arns):
                break
        return arns, page_sizes, pages

    # ListCapacityProviders can also hold other capacity providers, in an order that is not
    # based on creation time. Our _NUM_PROVIDERS freshly created providers are not guaranteed
    # to land next to each other in that list, so requiring a *single* contiguous MaxItems=1
    # walk to cover all of them at once could mean walking many unrelated items between two
    # of our own.
    #
    # Verify the "small MaxItems -> non-overlapping pages that together cover the item exactly
    # once" invariant *per created provider* instead: locate the (large-page) window that
    # contains a given provider, then resume pagination from that same server-side cursor
    # position with MaxItems=1 until that specific provider appears. This keeps each
    # provider's strict verification bounded by its own neighborhood in the list rather than by
    # the distance between unrelated providers.
    def _locate_windows(arns, max_items=50, max_pages=2000):
        """Single forward pass over ListCapacityProviders (paged with max_items) that locates,
        for every outstanding ARN, the marker at the start of the page containing it.

        Doing this as one shared sweep, instead of re-walking the whole list from scratch once
        per created provider, keeps the number of ListCapacityProviders round trips per poll
        attempt bounded by the list length itself rather than by len(arns) * list length.

        Also records how far the sweep actually got (pages walked, items seen, whether it
        reached the true end of the list or was cut off by max_pages) in _last_locate_stats, so
        a "never showed up" failure can say whether the sweep exhausted the list or merely ran
        out of round trips against a long list.
        """
        remaining = set(arns)
        found: dict[str, object] = {}
        marker = None
        pages = 0
        total_items = 0
        reached_end = False
        for _ in range(max_pages):
            begin_marker = marker
            kwargs = {"MaxItems": max_items}
            if marker:
                kwargs["Marker"] = marker
            resp = lam.list_capacity_providers(**kwargs)
            items = resp.get("CapacityProviders", [])
            pages += 1
            total_items += len(items)
            arns_here = {item.get("CapacityProviderArn") for item in items}
            for arn in list(remaining):
                if arn in arns_here:
                    found[arn] = begin_marker
                    remaining.discard(arn)
            if not remaining:
                break
            marker = resp.get("NextMarker")
            if not marker:
                reached_end = True
                break
        _last_locate_stats.update(pages=pages, total_items=total_items, reached_end=reached_end)
        return found

    def _probe_all():
        windows = _locate_windows(created_arns)
        results = {}
        for arn in created_arns:
            # The marker for the *first* page is legitimately None -- it means "start of the
            # list", not "absent". Testing `arn not in windows` (rather than
            # `windows.get(arn) is None`) is required so a provider found on page one is not
            # misread as never-found when the whole ListCapacityProviders collection fits on
            # a single 50-item page.
            if arn not in windows:
                results[arn] = None
            else:
                begin_marker = windows[arn]
                results[arn] = _sweep(1, start_marker=begin_marker, stop_when=lambda ars: arn in ars, max_pages=200)
        return results

    # ListCapacityProviders can lag GetCapacityProvider's "Active" status by more than a few
    # seconds, so we poll with a bounded budget rather than assuming instant visibility. We
    # re-locate every outstanding provider's window from scratch on every attempt (in one shared
    # sweep -- see _locate_windows) since the index can shift as other providers are created or
    # deleted.
    results = _poll_until(
        _probe_all,
        lambda r: all(v is not None and arn in v[0] for arn, v in r.items()),
        timeout_s=180.0,
        interval_s=10.0,
    )

    for arn, result in results.items():
        name = arn_to_name.get(arn, arn)
        assert result is not None, (
            f"capacity provider {name} ({arn}) never showed up while paginating (MaxItems=50 locate "
            f"sweep); last sweep walked {_last_locate_stats.get('pages')} page(s) covering "
            f"{_last_locate_stats.get('total_items')} item(s), reached_end_of_list="
            f"{_last_locate_stats.get('reached_end')}"
        )
        arns, page_sizes, _pages = result
        assert arn in arns, f"capacity provider {name} ({arn}) missing from its own MaxItems=1 paginated window"
        for size in page_sizes:
            assert size <= 1, f"page exceeded requested MaxItems=1: {size} items"
        assert arns.count(arn) == 1, (
            f"capacity provider {name} ({arn}) appeared more than once while paginating with MaxItems=1"
        )
        assert len(arns) == len(set(arns)), (
            f"paginated MaxItems=1 window for {name} ({arn}) returned a duplicate capacity provider arn"
        )


def _default_network(ec2, *, ctx) -> tuple[list[str], str]:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("unreachable: no shared network VPC available to build a CapacityProviderVpcConfig")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("unreachable: shared network has no subnets")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("unreachable: shared network has no default security group")
    return subnet_ids, sgs[0]["GroupId"]


def _create_operator_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-cpoperator-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_capacity_providers(ctx, lam, subnet_ids, sg_id, role_arn, count) -> dict[str, str]:
    name_to_arn: dict[str, str] = {}
    last_exc = None
    for i in range(count):
        name = ctx.unique_name(f"sim2real-behav-cp{i}-")
        # Bounded to a modest total (6 * 2s = 12s worst case per provider), since providers
        # are created sequentially and this budget multiplies by count.
        for _ in range(6):  # tolerate IAM propagation delay for the fresh operator role
            try:
                created = lam.create_capacity_provider(
                    CapacityProviderName=name,
                    VpcConfig={"SecurityGroupIds": [sg_id], "SubnetIds": subnet_ids},
                    PermissionsConfig={"CapacityProviderOperatorRoleArn": role_arn},
                    Tags={"sim2real:managed": "true"},
                )
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in ("InvalidParameterValueException", "ResourceConflictException"):
                    last_exc = exc
                    time.sleep(2)
                    continue
                raise
        else:
            raise last_exc
        ctx.on_cleanup(lambda n=name: _delete_capacity_provider_quietly(lam, n))
        name_to_arn[name] = created["CapacityProvider"]["CapacityProviderArn"]

    # Capacity providers take a while to provision (VPC ENIs etc.) and ListCapacityProviders
    # only needs to (eventually) reflect them once they exist, but to keep this check fast and
    # deterministic we wait for each one to leave the transient "Creating" state before we start
    # asserting anything about how it shows up in a paginated sweep.
    #
    # Provisioning happens concurrently for all created providers (we kicked off every
    # CreateCapacityProvider call before this point), so we must poll them concurrently too:
    # waiting on each name in its own sequential timeout window (as if one provider's transition
    # only starts once the previous one finished) multiplies the wait by len(names) and blows the
    # overall check budget even though the providers are, in reality, all becoming Active in
    # parallel on AWS's side.
    states = {name: None for name in name_to_arn}

    def _probe_all():
        for name in name_to_arn:
            if states[name] not in ("Active", "Failed"):
                states[name] = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]["State"]
        return dict(states)

    states = _poll_until(
        _probe_all,
        lambda result: all(s in ("Active", "Failed") for s in result.values()),
        timeout_s=60.0,
        interval_s=5.0,
    )
    for name, state in states.items():
        assert state == "Active", f"capacity provider {name} entered {state} instead of Active"

    return name_to_arn


def _delete_capacity_provider_quietly(lam, name: str) -> None:
    try:
        lam.delete_capacity_provider(CapacityProviderName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
