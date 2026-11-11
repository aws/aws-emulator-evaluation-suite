"""aggregation-authorization-tags-round-trip-and-deleted-not-found."""

from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aggregation-authorization-tags-round-trip-and-deleted-not-found"
GROUP = "tagging"
SERVICES = ["config"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:config-aggregation-authorization",
)
def run(ctx) -> None:
    """Tags given to PutAggregationAuthorization, TagResource and UntagResource read back exactly
    through ListTagsForResource on the authorization ARN; after delete that ARN is not found.

    Reference: https://docs.aws.amazon.com/config/latest/APIReference/API_ListTagsForResource.html
    """
    cfg = ctx.client("config")
    account_id = ctx.account
    region = ctx.region
    deleted = []

    def _matching():
        return [
            a
            for a in cfg.describe_aggregation_authorizations()["AggregationAuthorizations"]
            if a["AuthorizedAccountId"] == account_id and a["AuthorizedAwsRegion"] == region
        ]

    if _matching():
        raise RuntimeError(
            "precondition: an aggregation authorization for the caller's own account in this "
            "region already exists; this check creates and deletes its own"
        )

    arn = cfg.put_aggregation_authorization(
        AuthorizedAccountId=account_id,
        AuthorizedAwsRegion=region,
        Tags=[{"Key": "team", "Value": "audit"}, {"Key": "env", "Value": "dev"}],
    )["AggregationAuthorization"]["AggregationAuthorizationArn"]
    ctx.on_cleanup(lambda: deleted or _delete_authorization(cfg, account_id, region))

    form = (
        rf"arn:[a-z-]+:config:{re.escape(region)}:{account_id}:"
        rf"aggregation-authorization/{account_id}/{re.escape(region)}"
    )
    assert re.fullmatch(form, arn), f"AggregationAuthorizationArn {arn!r} does not match {form!r}"

    got = _tags(cfg, arn)
    assert got == {"team": "audit", "env": "dev"}, f"create-time tags read back as {got!r}"

    cfg.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "owner", "Value": "platform"}, {"Key": "env", "Value": "prod"}],
    )
    got = _tags(cfg, arn)
    want = {"team": "audit", "env": "prod", "owner": "platform"}
    assert got == want, f"after TagResource the tags read back as {got!r}, expected {want!r}"

    cfg.untag_resource(ResourceArn=arn, TagKeys=["team"])
    got = _tags(cfg, arn)
    want = {"env": "prod", "owner": "platform"}
    assert got == want, f"after UntagResource the tags read back as {got!r}, expected {want!r}"

    cfg.delete_aggregation_authorization(AuthorizedAccountId=account_id, AuthorizedAwsRegion=region)
    deleted.append(True)
    assert _matching() == [], "the authorization is still listed after delete"

    want_err = (
        "ResourceNotFoundException",
        f"Resource {arn} does not exist for account {account_id}",
    )
    err = _error(lambda: cfg.list_tags_for_resource(ResourceArn=arn))
    assert err == want_err, (
        f"ListTagsForResource after delete returned {err!r}, expected {want_err!r}"
    )

    err = _error(
        lambda: cfg.tag_resource(ResourceArn=arn, Tags=[{"Key": "late", "Value": "write"}])
    )
    assert err == want_err, f"TagResource after delete returned {err!r}, expected {want_err!r}"


# ===== helpers =====


def _tags(cfg, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=arn)["Tags"]}


def _error(fn) -> tuple:
    """(code, message) of the AWS error ``fn`` raises. Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"call unexpectedly succeeded and returned {result!r}")


def _delete_authorization(cfg, account_id: str, region: str) -> None:
    try:
        cfg.delete_aggregation_authorization(
            AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAggregationAuthorizationException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
