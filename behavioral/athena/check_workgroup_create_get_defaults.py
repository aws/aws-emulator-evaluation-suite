"""workgroup-create-get-defaults."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "workgroup-create-get-defaults"
GROUP = 'workgroup'
SERVICES = ['athena']

def _empty_and_delete_bucket(s3, bucket):
    """Teardown: empty and delete the results bucket; only an already-gone bucket is tolerated."""
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                )
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _output_location(ctx):
    """Create an Athena query-results bucket (region-correct) and return its s3:// prefix."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 rejects CreateBucketConfiguration entirely; every other region requires it.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "workgroup-create-get-defaults"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return f"s3://{bucket}/results/"

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkGroup persists config/state=ENABLED; re-creating the same name conflicts; deleted, it is gone."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")
    loc = _output_location(ctx)
    athena.create_work_group(
        Name=name,
        Description="initial description",
        Configuration={
            "ResultConfiguration": {"OutputLocation": loc},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[
            {"Key": "sim2real", "Value": "workgroup-create-get-defaults"},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: _delete_work_group_if_present(athena, name))

    got = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert got["Name"] == name, f"expected Name={name!r}, got {got['Name']!r}"
    assert got["State"] == "ENABLED", f"expected State='ENABLED', got {got['State']!r}"
    assert got["Description"] == "initial description", (
        f"expected Description='initial description', got {got['Description']!r}"
    )
    assert got["Configuration"]["EnforceWorkGroupConfiguration"] is True, (
        "expected EnforceWorkGroupConfiguration=True, got "
        f"{got['Configuration']['EnforceWorkGroupConfiguration']!r}"
    )
    got_loc = got["Configuration"].get("ResultConfiguration", {}).get("OutputLocation")
    assert got_loc == loc, f"expected ResultConfiguration.OutputLocation={loc!r}, got {got_loc!r}"
    wg_arn = f"arn:aws:athena:{ctx.region}:{ctx.account}:workgroup/{name}"
    wg_tags = athena.list_tags_for_resource(ResourceARN=wg_arn)["Tags"]
    want_tag = {"Key": "sim2real", "Value": "workgroup-create-get-defaults"}
    assert want_tag in wg_tags, f"expected tag {want_tag!r} on {wg_arn}, got {wg_tags!r}"

    # Overly-permissive boundary lives inline here rather than as a
    # separate padded "duplicate name" check: re-creating the same
    # WorkGroup name with different parameters MUST fail, not silently
    # overwrite the existing one.
    code, status, message = _error(lambda: athena.create_work_group(Name=name, Description="different description"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for the duplicate CreateWorkGroup, got {status}"
    expected_message = "WorkGroup is already created"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # original config must be untouched by the failed duplicate attempt
    still_there = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert still_there["Description"] == "initial description", (
        f"duplicate create mutated existing workgroup: {still_there['Description']!r}"
    )

    # Delete it, then prove it gone: unreadable, unlisted, and not updatable.
    athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    code, status, message = _error(lambda: athena.get_work_group(WorkGroup=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException for the deleted workgroup, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for GetWorkGroup of the deleted workgroup, got {status}"
    expected_message = "WorkGroup is not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed, token = [], None
    while True:
        page = athena.list_work_groups(**({"NextToken": token} if token else {}))
        listed += [w["Name"] for w in page["WorkGroups"]]
        token = page.get("NextToken")
        if not token:
            break
    assert name not in listed, "the deleted workgroup is still listed by ListWorkGroups"
    code, status, message = _error(lambda: athena.update_work_group(WorkGroup=name, Description="post-delete update"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException updating the deleted workgroup, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for UpdateWorkGroup of the deleted workgroup, got {status}"
    expected_message = "WorkGroup is not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _delete_work_group_if_present(athena, name):
    """Teardown: delete the workgroup, tolerating one the check already deleted."""
    from botocore.exceptions import ClientError

    try:
        athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidRequestException":
            raise


def _error(fn):
    """Call fn(); return its botocore Error code, HTTP status and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return (
            e.response["Error"]["Code"],
            e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            e.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
