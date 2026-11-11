"""cfn-opensearch-vpc-domain-in-place-update-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-opensearch-vpc-domain-in-place-update-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "opensearch"]

#: A domain takes 10-30 minutes to create or delete; the cap only stops a hung poll.
_STACK_CAP_S = 2100.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1700.0
#: An access policy or tag change settles in minutes; DescribeDomain and ListTags lag it.
_PROPAGATE_CAP_S = 600.0
_GONE_CAP_S = 1200.0
_POLL_S = 3.0

_ENGINE_VERSION = "OpenSearch_2.19"
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
#: The reason on the extra UPDATE_IN_PROGRESS row CloudFormation may add to an update.
_CONSISTENCY_CHECK = "Eventual consistency check initiated"
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_ACCOUNT_ROOT = "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"

#: Access policies, a tag value and the actions they allow, per step. Modifying the access
#: policy and adding or removing tags do not start a blue/green deployment.
_STEPS = {"v1": "es:ESHttpGet", "v2": "es:ESHttp*"}


#: DescribeDomainChangeProgress stage names that only a blue/green deployment goes through.
_BLUE_GREEN_STAGES = frozenset(
    {
        "Creating a new environment",
        "Provisioning new nodes",
        "Traffic routing on new nodes",
        "Traffic routing on old nodes",
        "Preparing nodes for removal",
        "Copying shards to new nodes",
        "Terminating nodes",
        "Deleting older resources",
    }
)


def _not_found(domain_name: str) -> tuple[str, str]:
    """OpenSearch's refusal of a domain that no longer exists."""
    return "ResourceNotFoundException", f"Domain not found: {domain_name}"


def _template(domain_name: str, subnet_id: str, step: str) -> str:
    # One t3.small.search data node with 10 GiB gp3 in one private subnet: no public endpoint,
    # and the policy admits only principals of this account.
    resource = "arn:${AWS::Partition}:es:${AWS::Region}:${AWS::AccountId}:domain/" + domain_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Domain": {
                    "Type": "AWS::OpenSearchService::Domain",
                    "Properties": {
                        "DomainName": domain_name,
                        "EngineVersion": _ENGINE_VERSION,
                        "ClusterConfig": {
                            "InstanceType": "t3.small.search",
                            "InstanceCount": 1,
                            "DedicatedMasterEnabled": False,
                            "ZoneAwarenessEnabled": False,
                        },
                        "EBSOptions": {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
                        "EncryptionAtRestOptions": {"Enabled": True},
                        "NodeToNodeEncryptionOptions": {"Enabled": True},
                        "DomainEndpointOptions": {"EnforceHTTPS": True},
                        "VPCOptions": {"SubnetIds": [subnet_id]},
                        "AccessPolicies": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": {"Fn::Sub": _ACCOUNT_ROOT}},
                                    "Action": _STEPS[step],
                                    "Resource": {"Fn::Sub": resource + "/*"},
                                }
                            ],
                        },
                        "Tags": [{"Key": "sim2real-step", "Value": step}],
                    },
                },
            },
            "Outputs": {
                "DomainRef": {"Value": {"Ref": "Domain"}},
                "DomainId": {"Value": {"Fn::GetAtt": ["Domain", "Id"]}},
                "DomainArn": {"Value": {"Fn::GetAtt": ["Domain", "Arn"]}},
                "DomainEndpoint": {"Value": {"Fn::GetAtt": ["Domain", "DomainEndpoint"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation VPC domain reads back as templated, updates in place, and is gone on delete.

    An access-policy and tag change keeps the DomainId and ARN; delete: ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-opensearchservice-domain.html
    """
    cfn = ctx.client("cloudformation")
    osc = ctx.client("opensearch")
    network = ctx.network(private=True)
    subnet_id = network.private_subnet_ids[0]
    zone = next(az for az, sn in network.private_subnets.items() if sn == subnet_id)
    domain_name = _domain_name(ctx)
    stack_name = ctx.unique_name("sim2real-cfnosd-stack-")
    ref = {"stack": stack_name}

    # A VPC domain needs the account's OpenSearch service-linked role.
    _ensure_service_linked_role(ctx)
    # Teardown waits on one deadline of its own: the body's deadline does not bound cleanup.
    limit: dict = {}
    ctx.on_cleanup(lambda: _delete_domain(osc, domain_name))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))

    # ---- 1. create: CloudFormation's view and OpenSearch's view
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(domain_name, subnet_id, "v1"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition, account = ref["stack"].split(":")[1], ref["stack"].split(":")[4]
    assert _physical_ids(cfn, ref["stack"])["Domain"] == domain_name, (
        f"the domain's physical id must be its name {domain_name!r}"
    )
    want_vpc = {
        "VPCId": network.vpc_id,
        "SubnetIds": [subnet_id],
        "AvailabilityZones": [zone],
        # No SecurityGroupIds in the template: the domain uses the VPC's default group.
        "SecurityGroupIds": [network.security_group_id],
    }
    status = _assert_domain(ctx, osc, domain_name, partition, account, "v1", want_vpc)
    want_outputs = {
        "DomainRef": domain_name,
        "DomainId": status["DomainId"],
        "DomainArn": f"arn:{partition}:es:{ctx.region}:{account}:domain/{domain_name}",
        "DomainEndpoint": status["Endpoints"]["vpc"],
    }
    assert _outputs(stack) == want_outputs, f"Ref and GetAtt outputs {_outputs(stack)!r}"
    _assert_tags(ctx, osc, want_outputs["DomainArn"], stack_name, "v1")

    # ---- 2. in-place: a wider access policy and a new tag value, the same domain
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(domain_name, subnet_id, "v2"), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Domain"), domain_name, "Domain")
    after = _assert_domain(ctx, osc, domain_name, partition, account, "v2", want_vpc)
    assert (after["DomainId"], after["ARN"]) == (status["DomainId"], want_outputs["DomainArn"]), (
        f"an in-place update keeps DomainId and ARN, read {(after['DomainId'], after['ARN'])!r}"
    )
    assert _outputs(stack) == want_outputs, f"outputs after the update {_outputs(stack)!r}"
    _assert_no_blue_green(ctx, osc, domain_name)
    _assert_tags(ctx, osc, want_outputs["DomainArn"], stack_name, "v2")

    # ---- 3. delete: OpenSearch no longer knows the domain
    _delete_stack(ctx, cfn, ref["stack"], _STACK_CAP_S)
    got = _wait_error(
        ctx,
        lambda: osc.describe_domain(DomainName=domain_name),
        _not_found(domain_name)[0],
        f"domain {domain_name}",
    )
    assert got == _not_found(domain_name), f"DescribeDomain after the stack delete answered {got!r}"


def _domain_name(ctx) -> str:
    """A unique lowercase domain name of 25 characters (the limit is 28)."""
    return ctx.unique_name("sim2real-osd-").lower()


def _policy(domain_name: str, partition: str, account: str, region: str, step: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
                "Action": _STEPS[step],
                "Resource": f"arn:{partition}:es:{region}:{account}:domain/{domain_name}/*",
            }
        ],
    }


def _assert_domain(ctx, osc, domain_name, partition, account, step, want_vpc) -> dict:
    """DescribeDomain reports every templated setting exactly once the domain is not processing.

    The read is polled: a configuration change applies after the stack update completes.
    """
    want_policy = _policy(domain_name, partition, account, ctx.region, step)
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if not status["Processing"] and json.loads(status["AccessPolicies"]) == want_policy:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {domain_name} showed step {step}")
            raise AssertionError(
                f"DescribeDomain {domain_name}: Processing {status['Processing']!r}, "
                f"AccessPolicies {status['AccessPolicies']!r}, expected {want_policy!r}"
            )
        time.sleep(_POLL_S)
    cluster = status["ClusterConfig"]
    ebs = status["EBSOptions"]
    vpc = status["VPCOptions"]
    got = {
        "DomainName": status["DomainName"],
        "Created": status["Created"],
        "Deleted": status["Deleted"],
        "EngineVersion": status["EngineVersion"],
        "InstanceType": cluster["InstanceType"],
        "InstanceCount": cluster["InstanceCount"],
        "DedicatedMasterEnabled": cluster["DedicatedMasterEnabled"],
        "ZoneAwarenessEnabled": cluster["ZoneAwarenessEnabled"],
        "EBS": (ebs["EBSEnabled"], ebs["VolumeType"], ebs["VolumeSize"]),
        "EncryptionAtRest": status["EncryptionAtRestOptions"]["Enabled"],
        "NodeToNode": status["NodeToNodeEncryptionOptions"]["Enabled"],
        "EnforceHTTPS": status["DomainEndpointOptions"]["EnforceHTTPS"],
        "VPC": {k: vpc.get(k) for k in want_vpc},
        "PublicEndpoint": status.get("Endpoint"),
        "EndpointKeys": sorted(status.get("Endpoints", {})),
    }
    want = {
        "DomainName": domain_name,
        "Created": True,
        "Deleted": False,
        "EngineVersion": _ENGINE_VERSION,
        "InstanceType": "t3.small.search",
        "InstanceCount": 1,
        "DedicatedMasterEnabled": False,
        "ZoneAwarenessEnabled": False,
        "EBS": (True, "gp3", 10),
        "EncryptionAtRest": True,
        "NodeToNode": True,
        "EnforceHTTPS": True,
        "VPC": want_vpc,
        # A VPC domain has only a VPC endpoint, never a public one.
        "PublicEndpoint": None,
        "EndpointKeys": ["vpc"],
    }
    assert got == want, f"DescribeDomain {domain_name}: {got!r}, expected {want!r}"
    return status


def _assert_no_blue_green(ctx, osc, domain_name: str) -> None:
    """DescribeDomainChangeProgress reports the update COMPLETED with no blue/green stage.

    Modifying the access policy and tags is a dynamic update; polled until the change completes.
    """
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        progress = osc.describe_domain_change_progress(DomainName=domain_name).get(
            "ChangeProgressStatus", {}
        )
        if progress.get("Status") == "COMPLETED":
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {domain_name}'s change completed")
            raise AssertionError(f"DescribeDomainChangeProgress {domain_name}: {progress!r}")
        time.sleep(_POLL_S)
    stages = [stage.get("Name") for stage in progress.get("ChangeProgressStages") or []]
    blue_green = sorted(set(stages) & _BLUE_GREEN_STAGES)
    assert blue_green == [], (
        f"the access-policy and tag update ran blue/green stages {blue_green!r}: {progress!r}"
    )


def _assert_tags(ctx, osc, arn: str, stack_name: str, step: str) -> None:
    """ListTags minus aws:* is the stack's tag plus the template's step tag, polled."""
    want = {"sim2real": CHECK, "sim2real-step": step}
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = {
            t["Key"]: t["Value"]
            for t in osc.list_tags(ARN=arn)["TagList"]
            if not t["Key"].startswith("aws:")
        }
        if got == want:
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {arn} showed tags {want!r}")
            raise AssertionError(f"ListTags {arn} ({stack_name}): {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _ensure_service_linked_role(ctx) -> None:
    """Create or adopt the OpenSearch service-linked role; never deleted (account-level)."""
    try:
        ctx.client("iam").create_service_linked_role(
            AWSServiceName="opensearchservice.amazonaws.com"
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "InvalidInput" and "taken" in err.get("Message", "")):
            raise


def _delete_domain(osc, domain_name: str) -> None:
    """Delete a domain the stack left behind; not-found is already deleted."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. With ctx None (teardown) it is cap_s.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*.

    CloudFormation may add one UPDATE_IN_PROGRESS row for its eventual consistency check.
    """
    statuses = [status for status, _, _ in rows]
    reasons = [reason for _, reason, _ in rows]
    plain = statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"]
    checked = statuses == ["UPDATE_IN_PROGRESS", "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"] and (
        reasons[1] == _CONSISTENCY_CHECK
    )
    assert (plain or checked) and reasons[0] != _REPLACING, (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str, cap_s: float) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, cap_s), "DELETE_COMPLETE")


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _teardown_stack(cfn, ref: dict, limit: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Every wait shares the one deadline in *limit*, so the whole teardown fits its cap.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"], _remaining(limit))
    _delete_stack(None, cfn, stack["StackId"], _remaining(limit))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
