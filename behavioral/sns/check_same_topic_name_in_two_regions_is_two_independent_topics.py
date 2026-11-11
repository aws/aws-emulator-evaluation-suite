"""same-topic-name-in-two-regions-is-two-independent-topics."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "same-topic-name-in-two-regions-is-two-independent-topics"
GROUP = "cross-region"
SERVICES = ["sns"]


def _other_region(region: str) -> str:
    """A second commercial region of the same account (region-pinned by design)."""
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _listed(sns, arn: str) -> bool:
    return any(t["TopicArn"] == arn for p in sns.get_paginator("list_topics").paginate()
               for t in p["Topics"])


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One topic name in two regions yields two independent topics whose ARNs differ only in the
    region: attributes, tags and listings stay separate, and deleting one leaves the other.
    """
    home = ctx.region
    away = _other_region(home)
    sns = ctx.client("sns")
    sns_away = ctx.client("sns", region=away)
    name = ctx.unique_name("sim2real-behav-sns-twin-")

    a = sns.create_topic(Name=name, Attributes={"DisplayName": "home twin"},
                         Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=a))
    b = sns_away.create_topic(Name=name, Attributes={"DisplayName": "away twin"},
                              Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns_away.delete_topic(TopicArn=b))

    pa, pb = a.split(":"), b.split(":")
    assert (pa[3], pb[3]) == (home, away), f"the twins' ARN regions are {pa[3]!r} and {pb[3]!r}"
    assert pa[:3] + pa[4:] == pb[:3] + pb[4:], "the twins' ARNs must differ only in the region field"

    sns.set_topic_attributes(TopicArn=a, AttributeName="DisplayName", AttributeValue="home changed")
    sns.tag_resource(ResourceArn=a, Tags=[{"Key": "side", "Value": "home"}])
    da = sns.get_topic_attributes(TopicArn=a)["Attributes"].get("DisplayName")
    db = sns_away.get_topic_attributes(TopicArn=b)["Attributes"].get("DisplayName")
    assert (da, db) == ("home changed", "away twin"), (
        f"each twin must keep its own DisplayName; got home {da!r}, away {db!r}")
    away_tags = {t["Key"] for t in sns_away.list_tags_for_resource(ResourceArn=b)["Tags"]}
    assert away_tags == {"sim2real"}, f"a tag added to the home twin appeared on the away twin: {sorted(away_tags)!r}"

    assert (_listed(sns, a), _listed(sns, b)) == (True, False), (
        "the home region must list its own twin and not the other region's")
    assert (_listed(sns_away, b), _listed(sns_away, a)) == (True, False), (
        "the away region must list its own twin and not the other region's")

    sns.delete_topic(TopicArn=a)
    # Topic deletion is eventually consistent.
    deadline = time.monotonic() + 60
    while True:
        try:
            sns.get_topic_attributes(TopicArn=a)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            break
        assert time.monotonic() < deadline, "the deleted home twin is still readable"
        time.sleep(2)
    assert code == "NotFound", f"reading the deleted home twin gave {code!r}"
    survivor = sns_away.get_topic_attributes(TopicArn=b)["Attributes"]
    assert (survivor.get("TopicArn"), survivor.get("DisplayName")) == (b, "away twin"), (
        "deleting the home twin disturbed the away twin")
    code, message = _error(lambda: sns.get_topic_attributes(TopicArn=a))
    assert (code, message) == ("NotFound", "Topic does not exist"), (
        f"the deleted twin must read as missing; got {code!r}: {message!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
