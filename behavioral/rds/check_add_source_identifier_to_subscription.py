"""add-source-identifier-to-subscription."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-source-identifier-to-subscription"
GROUP = 'events'
SERVICES = ['rds']

ERR_SOURCE_NOT_FOUND = "SourceNotFound"

def _default_param_family(rds, engine: str) -> str:
    """DBParameterGroupFamily of the current default version for *engine*."""
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddSourceIdentifierToSubscription adds a valid source id to an active subscription, shown
    in DescribeEventSubscriptions SourceIdsList; an unknown source id rejects with SourceNotFound."""
    rds = ctx.client("rds")
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"),
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sub_name = ctx.unique_name("sim2real-behav-evsub-")
    rds.create_event_subscription(
        SubscriptionName=sub_name,
        SnsTopicArn=topic_arn,
        SourceType="db-parameter-group",
        Enabled=True,
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_event_subscription(SubscriptionName=sub_name))

    def _describe():
        subs = rds.describe_event_subscriptions(SubscriptionName=sub_name).get(
            "EventSubscriptionsList", []
        )
        return subs[0] if subs else None

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        sub = _describe()
        if sub is not None and sub.get("Status") == "active":
            break
        time.sleep(3)
    else:
        raise AssertionError(f"event subscription {sub_name} did not become active in time")

    pg_name = ctx.unique_name("sim2real-behav-pg-src-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily=_default_param_family(rds, "mysql"),
        Description="sim2real behavioral check source",
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))

    bogus_pg = ctx.unique_name("sim2real-behav-pg-missing-")
    code = message = None
    try:
        rds.add_source_identifier_to_subscription(
            SubscriptionName=sub_name, SourceIdentifier=bogus_pg
        )
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_SOURCE_NOT_FOUND, f"unexpected error code: {code!r}"
    assert message == f"Could not find source :{bogus_pg}", message

    rds.add_source_identifier_to_subscription(
        SubscriptionName=sub_name, SourceIdentifier=pg_name
    )
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        sub = _describe()
        if sub is not None and pg_name in (sub.get("SourceIdsList") or []):
            break
        time.sleep(3)
    else:
        raise AssertionError(f"source id {pg_name} not attached in time")
    assert sub["SourceIdsList"] == [pg_name], (
        f"expected SourceIdsList == [{pg_name!r}], got {sub['SourceIdsList']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
