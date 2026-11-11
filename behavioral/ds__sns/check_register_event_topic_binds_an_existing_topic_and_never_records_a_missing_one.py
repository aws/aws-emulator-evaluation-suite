"""register-event-topic-binds-an-existing-topic-and-never-records-a-missing-one."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where Directory Service cannot place domain controllers (CreateMicrosoftAD: "Failed to
# locate Availability Zone"); subnets there are never offered to it. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "register-event-topic-binds-an-existing-topic-and-never-records-a-missing-one"
GROUP = "eventing"
SERVICES = ["ds", "sns"]

_PASSWORD = "Sim2Real#Pass99"
_SHARED_TAG_KEY = "sim2real-ds-shared"
_SHARED_TAG_VALUE = "behavioral-shared-mad"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}
_DIRECTORY_DEADLINE_S = 3600.0
_REGISTERED_DEADLINE_S = 300.0
# TopicStatus, verbatim from the model's enum. Every Status observed must come from here, and
# 'Registered' is the only one that means the binding took.
_TOPIC_STATUS_ENUM = ("Registered", "Topic not found", "Failed", "Deleted")


# Not-found codes of the teardown calls (DeleteDirectory, DeregisterEventTopic, SNS DeleteTopic).
_GONE = frozenset({"EntityDoesNotExistException", "NotFound"})
# DeregisterEventTopic's refusal for a topic that is not (or no longer) registered.
_NOT_REGISTERED = ("ClientException", "has not been registered for directory")


def _swallow_not_found(fn):
    """Run a teardown call: a resource already gone is fine; any other error raises. Cleanup only,
    never on an assertion path."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") in _GONE:
            return
        code, needle = _NOT_REGISTERED
        if err.get("Code") == code and needle in err.get("Message", ""):
            return
        raise


def _poll(fn, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll fn() until pred(result). Raises on timeout, naming what it waited for."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observation was {last!r}"
            )
        time.sleep(interval_s)


def _describe_directory(ds, directory_id: str):
    try:
        found = ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
            return None
        raise
    descriptions = found.get("DirectoryDescriptions") or []
    return descriptions[0] if descriptions else None


def _topics(ds, directory_id: str, **extra) -> list:
    """The EventTopics DescribeEventTopics reports; every consumer compares or searches the list,
    so an empty default never supplies an asserted answer."""
    return ds.describe_event_topics(DirectoryId=directory_id, **extra).get("EventTopics") or []


def _find(topics: list, topic_name: str):
    """The single EventTopic entry for topic_name, or None. Raises if the service reports it twice."""
    matches = [t for t in topics if t.get("TopicName") == topic_name]
    assert len(matches) <= 1, (
        f"expected at most one EventTopics entry per topic name, got {len(matches)} for "
        f"{topic_name!r}: {matches!r}"
    )
    return matches[0] if matches else None


def _statements(policy_json) -> list:
    """The Statement list of an SNS access policy, parsed. An SNS topic always has a policy, so a
    missing one is a real failure and is asserted rather than defaulted away."""
    assert policy_json, (
        f"expected the SNS topic to report an access Policy attribute, got {policy_json!r}"
    )
    parsed = json.loads(policy_json)
    statements = parsed.get("Statement")
    assert isinstance(statements, list), (
        f"expected the SNS access policy to carry a Statement list, got {parsed!r}"
    )
    return statements


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The account's shared network and two subnets in DISTINCT AZs, derived not hardcoded; a
    shared VPC because the default VPC quota of five would otherwise cap concurrency."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        "expected this account to have a shared network, got none; a Managed Microsoft AD requires a "
        "VPC with two subnets in distinct availability zones"
    )
    vpc = vpcs[0]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc["VpcId"]]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_zone: dict = {}
    for subnet in sorted(subnets, key=lambda x: x["SubnetId"]):
        by_zone.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    zones = sorted(by_zone)
    assert len(zones) >= 2, (
        f"expected >= 2 available zones with a subnet in each, got {len(zones)}: {by_zone!r} in "
        f"{vpc['VpcId']!r}"
    )
    return vpc["VpcId"], [by_zone[z] for z in zones[:2]]


def _adopt_or_create_directory(ctx, ds, ec2) -> tuple:
    """An Active Standard AWS Managed Microsoft AD -> (directory_id, fqdn), adopted or created.
    Only a directory this call CREATED is torn down; an adopted one is shared with other checks."""
    for existing in ds.describe_directories().get("DirectoryDescriptions") or []:
        if existing.get("Type") != "MicrosoftAD" or not existing.get("DirectoryId"):
            continue
        listed = ds.list_tags_for_resource(ResourceId=existing["DirectoryId"]).get("Tags") or []
        if {"Key": _SHARED_TAG_KEY, "Value": _SHARED_TAG_VALUE} not in listed:
            continue
        adopted = _poll(
            lambda did=existing["DirectoryId"]: _describe_directory(ds, did) or {},
            lambda d: d.get("Stage") in _CREATE_TERMINAL,
            timeout_s=_DIRECTORY_DEADLINE_S, interval_s=20.0,
            what=f"the adopted shared directory {existing['DirectoryId']} to leave its transient "
                 f"creation stages",
        )
        assert adopted.get("Stage") == "Active", (
            f"expected the adopted shared directory {existing['DirectoryId']!r} to be Stage "
            f"'Active', got {adopted.get('Stage')!r} (StageReason={adopted.get('StageReason')!r})"
        )
        return existing["DirectoryId"], adopted["Name"]

    vpc_id, subnet_ids = _default_vpc_subnets(ec2, ctx=ctx)
    fqdn = f"{ctx.unique_name('sim2real-behav-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=fqdn, ShortName="SIM2REAL", Password=_PASSWORD, Edition="Standard",
        Description=f"sim2real behavioral {CHECK}",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "behavioral"},
              {"Key": "sim2real-check", "Value": CHECK},
              {"Key": _SHARED_TAG_KEY, "Value": _SHARED_TAG_VALUE}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _swallow_not_found(
        lambda: ds.delete_directory(DirectoryId=directory_id)))
    created = _poll(
        lambda: _describe_directory(ds, directory_id) or {},
        lambda d: d.get("Stage") in _CREATE_TERMINAL,
        timeout_s=_DIRECTORY_DEADLINE_S, interval_s=20.0,
        what=f"the new directory {directory_id} to reach a terminal creation stage",
    )
    assert created.get("Stage") == "Active", (
        f"expected the new directory to reach Stage 'Active', got {created.get('Stage')!r} "
        f"(StageReason={created.get('StageReason')!r})"
    )
    return directory_id, fqdn


@tags("axis:rejection", "cap:c1", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterEventTopic binds an existing SNS topic ('Registered', SNS's ARN) without touching its
    policy, never records a missing topic as 'Registered', and succeeds once that topic is created.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/ms_ad_enable_notifications.html
    """
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    sns = ctx.client("sns")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "expected STS to report the caller account id, got an empty value"

    directory_id, _fqdn = _adopt_or_create_directory(ctx, ds, ec2)

    # --- (1) A real topic, and its policy BEFORE Directory Service is told about it.
    real_name = ctx.unique_name("sim2real-ds-evt-")
    real_arn = sns.create_topic(
        Name=real_name,
        Tags=[{"Key": "sim2real", "Value": "behavioral"},
              {"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: sns.delete_topic(TopicArn=real_arn)))
    assert real_arn.endswith(f":{real_name}"), (
        f"expected SNS to mint an ARN ending in the topic name, expected a suffix of "
        f"{f':{real_name}'!r}, got {real_arn!r}"
    )
    assert f":{ctx.region}:" in real_arn and f":{account}:" in real_arn, (
        f"expected the topic ARN to name the region and account this check is signing for, expected "
        f"{ctx.region!r} and {account!r} in {real_arn!r}"
    )
    policy_before = _statements(
        sns.get_topic_attributes(TopicArn=real_arn)["Attributes"].get("Policy"))

    baseline = _topics(ds, directory_id)
    assert _find(baseline, real_name) is None, (
        f"expected the directory to have no registration for {real_name!r} before this check creates "
        f"one, got {baseline!r}"
    )

    # --- (2) POSITIVE CONTROL: register the real topic, and read the binding back.
    ds.register_event_topic(DirectoryId=directory_id, TopicName=real_name)
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: ds.deregister_event_topic(
        DirectoryId=directory_id, TopicName=real_name)))
    bound = _poll(
        lambda: _find(_topics(ds, directory_id), real_name),
        lambda entry: entry is not None and entry.get("Status") == "Registered",
        timeout_s=_REGISTERED_DEADLINE_S, interval_s=10.0,
        what=f"DescribeEventTopics to report {real_name!r} with TopicStatus 'Registered'",
    )
    assert bound.get("Status") == "Registered", (
        f"expected the registration of an existing topic to reach TopicStatus 'Registered', got "
        f"{bound.get('Status')!r} in {bound!r}"
    )
    assert bound.get("Status") in _TOPIC_STATUS_ENUM, (
        f"expected every TopicStatus to come from the modelled enum {_TOPIC_STATUS_ENUM!r}, got "
        f"{bound.get('Status')!r}"
    )
    # DERIVED, not pinned: the ARN Directory Service reports must be the one SNS minted.
    assert bound.get("TopicArn") == real_arn, (
        f"expected DescribeEventTopics to report the ARN SNS itself minted for {real_name!r}, "
        f"expected {real_arn!r}, got {bound.get('TopicArn')!r}"
    )
    assert bound.get("DirectoryId") == directory_id, (
        f"expected the registration to name the directory it was made against, expected "
        f"{directory_id!r}, got {bound.get('DirectoryId')!r}"
    )
    assert bound.get("CreatedDateTime") is not None, (
        f"expected a registration to be timestamped, got {bound!r}"
    )

    # --- (3) Read at the consumer: real AWS leaves the topic's access policy byte-for-byte unchanged
    # on a successful registration; Directory Service is authorized to publish without a
    # resource-policy grant.
    policy_after = _statements(
        sns.get_topic_attributes(TopicArn=real_arn)["Attributes"].get("Policy"))
    assert policy_after == policy_before, (
        f"expected a SUCCESSFUL RegisterEventTopic to leave the topic's own access policy "
        f"byte-for-byte unchanged, exactly as a REFUSED one does — got {policy_before!r} -> "
        f"{policy_after!r}"
    )
    assert not any(
        "directoryservice" in json.dumps(statement).lower()
        or "ds.amazonaws.com" in json.dumps(statement).lower()
        for statement in policy_after
    ), (
        f"expected no Directory Service statement in the topic policy after registration, got "
        f"{policy_after!r}"
    )

    # --- (4) BREAK EXACTLY ONE THING: a topic name SNS does not hold. Same directory, same call.
    missing_name = ctx.unique_name("sim2real-ds-evt-gone-")
    listed = sns.list_topics().get("Topics") or []
    assert not [t for t in listed if (t.get("TopicArn") or "").endswith(f":{missing_name}")], (
        f"the negative below requires {missing_name!r} to be genuinely absent from SNS, but "
        f"ListTopics already holds it"
    )
    try:
        ds.register_event_topic(DirectoryId=directory_id, TopicName=missing_name)
        refusal_code = None
    except ClientError as exc:
        refusal_code = exc.response.get("Error", {}).get("Code")
    # The model permits either refusal or a recorded non-'Registered' status, so both are accepted;
    # recording the missing topic as Registered, or a status outside the enum, fails.
    recorded = _find(_topics(ds, directory_id), missing_name)
    if refusal_code is None:
        assert recorded is not None, (
            f"expected an ACCEPTED RegisterEventTopic for the absent topic {missing_name!r} to be "
            f"visible in DescribeEventTopics with a status describing the missing topic, got no entry "
            f"at all — acceptance with no record is the one outcome neither mechanism allows"
        )
        assert recorded.get("Status") in _TOPIC_STATUS_ENUM, (
            f"expected the recorded status of the absent topic to come from the modelled enum "
            f"{_TOPIC_STATUS_ENUM!r}, got {recorded.get('Status')!r}"
        )
        assert recorded.get("Status") != "Registered", (
            f"expected a topic SNS does not hold NEVER to be reported as 'Registered' — that is "
            f"silent misconfiguration of the directory's only notification channel — got "
            f"{recorded!r}. The modelled enum has 'Topic not found' for exactly this case."
        )
        ctx.on_cleanup(lambda: _swallow_not_found(lambda: ds.deregister_event_topic(
            DirectoryId=directory_id, TopicName=missing_name)))
    else:
        assert recorded is None, (
            f"expected a REFUSED RegisterEventTopic ({refusal_code!r}) to record nothing, but "
            f"DescribeEventTopics reports {recorded!r} for {missing_name!r}"
        )
        assert refusal_code != "AccessDeniedException", (
            f"expected the refusal to be about the missing TOPIC, not about permissions — the "
            f"positive control two steps above proves these credentials can register a topic on this "
            f"directory — got {refusal_code!r}"
        )

    # The real registration is untouched by the failed one.
    assert _find(_topics(ds, directory_id), real_name).get("Status") == "Registered", (
        f"expected the earlier successful registration of {real_name!r} to survive the failed one, "
        f"got {_find(_topics(ds, directory_id), real_name)!r}"
    )

    # --- (5) RESTORE: create exactly the missing thing, then demand the identical call.
    missing_arn = sns.create_topic(
        Name=missing_name,
        Tags=[{"Key": "sim2real", "Value": "behavioral"},
              {"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: sns.delete_topic(TopicArn=missing_arn)))
    ds.register_event_topic(DirectoryId=directory_id, TopicName=missing_name)
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: ds.deregister_event_topic(
        DirectoryId=directory_id, TopicName=missing_name)))
    restored = _poll(
        lambda: _find(_topics(ds, directory_id), missing_name),
        lambda entry: entry is not None and entry.get("Status") == "Registered",
        timeout_s=_REGISTERED_DEADLINE_S, interval_s=10.0,
        what=f"the byte-identical RegisterEventTopic for {missing_name!r} to reach 'Registered' now "
             f"that SNS holds the topic — the restore beat that proves the earlier outcome was about "
             f"the topic and not about the target refusing everything",
    )
    assert restored.get("TopicArn") == missing_arn, (
        f"expected the restored registration to bind the ARN SNS just minted, expected "
        f"{missing_arn!r}, got {restored.get('TopicArn')!r}"
    )

    # --- (6) The TopicName filter selects, and Deregister really unbinds.
    filtered = _topics(ds, directory_id, TopicNames=[real_name])
    assert [t.get("TopicName") for t in filtered] == [real_name], (
        f"expected DescribeEventTopics filtered to {real_name!r} to return only that registration, "
        f"got {[t.get('TopicName') for t in filtered]!r}"
    )
    ds.deregister_event_topic(DirectoryId=directory_id, TopicName=real_name)
    after = _poll(
        lambda: _find(_topics(ds, directory_id), real_name),
        lambda entry: entry is None,
        timeout_s=_REGISTERED_DEADLINE_S, interval_s=10.0,
        what=f"DescribeEventTopics to stop reporting {real_name!r} after DeregisterEventTopic",
    )
    assert after is None, (
        f"expected DeregisterEventTopic to remove the registration entirely rather than leave a "
        f"tombstone, got {after!r}"
    )
    # And the OTHER registration is untouched — deregistration is scoped to the topic it named.
    survivor = _find(_topics(ds, directory_id), missing_name)
    assert survivor is not None and survivor.get("Status") == "Registered", (
        f"expected deregistering {real_name!r} to leave the registration of {missing_name!r} alone, "
        f"got {survivor!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
