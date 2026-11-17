"""create-tags-overwrites-a-key-and-describe-tags-pages-by-max-results."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tags-overwrites-a-key-and-describe-tags-pages-by-max-results"
GROUP = "tagging"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-tagging an existing key with CreateTags replaces its value rather than duplicating
    the tag; a resource-id filter returns the whole tag set regardless of MaxResults, while a
    key filter pages by MaxResults with a NextToken that can still trail the last real page."""
    ec2 = ctx.client("ec2")
    vpc_id = ctx.network().vpc_id

    group_name = ctx.unique_name("sim2real-tagpage-")
    sg_id = ec2.create_security_group(
        GroupName=group_name,
        Description="sim2real tag-overwrite and describe-tags pagination check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": group_name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    # --- overwrite: re-tagging the same key replaces the value, it does not duplicate it ---
    dup_key = ctx.unique_name("sim2real-dup-")
    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": dup_key, "Value": "v1"}])
    _assert_single_value(ec2, sg_id, dup_key, "v1")

    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": dup_key, "Value": "v2"}])
    _assert_single_value(ec2, sg_id, dup_key, "v2")

    # --- grow the resource's tag set to 10 (Name + dup_key + 8 more) for the resource-id read ---
    extra_prefix = ctx.unique_name("sim2real-extra-")
    extra = [{"Key": f"{extra_prefix}-{i:02d}", "Value": f"value-{i:02d}"} for i in range(8)]
    ec2.create_tags(Resources=[sg_id], Tags=extra)
    expected_keys = {"Name", dup_key} | {t["Key"] for t in extra}

    all_tags = _poll_until(
        lambda: _tags_of(ec2, sg_id),
        lambda found: len(found) == len(expected_keys),
        timeout_s=30,
        interval_s=2,
    )
    assert set(all_tags) == expected_keys, (
        f"expected tag keys {sorted(expected_keys)}, got {sorted(all_tags)}"
    )
    assert all_tags[dup_key] == "v2", (
        f"expected the overwritten key to hold the latest value 'v2', got {all_tags[dup_key]!r}"
    )

    # --- a further 10 never-overwritten keys, created in one call, for the pagination read
    # below: kept apart from dup_key so an overwrite's own convergence cannot be mistaken for
    # a pagination defect ---
    page_prefix = ctx.unique_name("sim2real-page-")
    page_tags = [{"Key": f"{page_prefix}-{i:02d}", "Value": f"value-{i:02d}"} for i in range(10)]
    ec2.create_tags(Resources=[sg_id], Tags=page_tags)
    unique_keys = {t["Key"] for t in page_tags}
    expected_keys = expected_keys | unique_keys
    _poll_until(
        lambda: _tags_of(ec2, sg_id),
        lambda found: len(found) == len(expected_keys),
        timeout_s=30,
        interval_s=2,
    )

    # --- pagination: MaxResults below the documented minimum of 5 is rejected ---
    code, message = _client_error(
        lambda: ec2.describe_tags(
            Filters=[{"Name": "resource-id", "Values": [sg_id]}], MaxResults=4
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_message = "Value ( 4 ) for parameter maxResults is invalid. Expecting a value greater than 5."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- a single resource-id filter returns that resource's whole tag set in one page,
    # regardless of MaxResults: there is only ever one resource to page through ---
    by_resource = ec2.describe_tags(
        Filters=[{"Name": "resource-id", "Values": [sg_id]}], MaxResults=5
    )
    assert len(by_resource["Tags"]) == len(expected_keys), (
        f"expected all {len(expected_keys)} of the resource's tags in one page, "
        f"got {len(by_resource['Tags'])}"
    )
    assert not by_resource.get("NextToken"), (
        f"expected no NextToken for a single resource-id filter, got {by_resource.get('NextToken')!r}"
    )

    # --- a key filter (no resource-id) pages normally: MaxResults=5 against 10 rows matching
    # these check-unique keys returns a first page of 5 with a NextToken, then the rest with
    # none. "Name" is excluded here: other resources in the account carry that key too, and a
    # key filter is account-wide, not scoped to this resource. ---
    key_filter = [{"Name": "key", "Values": sorted(unique_keys)}]
    page1 = ec2.describe_tags(Filters=key_filter, MaxResults=5)
    assert len(page1["Tags"]) == 5, f"expected a 5-tag first page, got {len(page1['Tags'])}"
    next_token = page1.get("NextToken")
    assert next_token, f"expected a NextToken on the first page, got {next_token!r}"

    page2 = ec2.describe_tags(Filters=key_filter, MaxResults=5, NextToken=next_token)
    assert len(page2["Tags"]) == 5, f"expected a 5-tag second page, got {len(page2['Tags'])}"

    # A NextToken can still trail the last page of real results; the exhausted page it points
    # to is empty and carries none of its own, so draining is what proves pagination ended,
    # never the mere absence of a token on the page before it.
    trailing_token = page2.get("NextToken")
    if trailing_token:
        page3 = ec2.describe_tags(Filters=key_filter, MaxResults=5, NextToken=trailing_token)
        assert page3["Tags"] == [], (
            f"expected the page after the trailing NextToken to be empty, got {page3['Tags']!r}"
        )
        assert not page3.get("NextToken"), (
            f"expected pagination to be exhausted, got a further NextToken {page3.get('NextToken')!r}"
        )

    page1_keys = {t["Key"] for t in page1["Tags"]}
    page2_keys = {t["Key"] for t in page2["Tags"]}
    assert not (page1_keys & page2_keys), (
        f"the two pages overlap on {page1_keys & page2_keys}, pagination must not repeat a tag"
    )
    assert page1_keys | page2_keys == unique_keys, (
        f"the two pages together cover {sorted(page1_keys | page2_keys)}, expected {sorted(unique_keys)}"
    )


def _tags_of(ec2, resource_id: str) -> dict:
    desc = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [resource_id]}])
    return {t["Key"]: t["Value"] for t in desc["Tags"]}


def _assert_single_value(ec2, resource_id: str, key: str, value: str) -> None:
    found = [t for t in ec2.describe_tags(
        Filters=[{"Name": "resource-id", "Values": [resource_id]}, {"Name": "key", "Values": [key]}]
    )["Tags"]]
    assert len(found) == 1, f"expected exactly one tag for key {key!r}, got {found!r}"
    assert found[0]["Value"] == value, (
        f"expected {key}={value!r}, DescribeTags returned {found[0]['Value']!r}"
    )


def _client_error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected SUCCESS raises, so a
    target accepting input real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
