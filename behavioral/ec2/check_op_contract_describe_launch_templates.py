"""op-contract-describe-launch-templates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-launch-templates"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLaunchTemplates finds a new template by name, by id and by a tag:<key> filter, each
    echoing its name, id, version 1 markers and tags; a fabricated id is rejected as Malformed."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-behav-lt-")
    tag_key = ctx.unique_name("sim2real-lt-key-")
    tag_value = ctx.unique_name("v-")
    sent_tags = [{"Key": "sim2real", "Value": "1"}, {"Key": tag_key, "Value": tag_value}]
    created = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": sent_tags}],
    )["LaunchTemplate"]
    lt_id = created["LaunchTemplateId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id),
                             "InvalidLaunchTemplateId.NotFound"))

    resp = ec2.describe_launch_templates(LaunchTemplateNames=[name])
    assert len(resp["LaunchTemplates"]) == 1, (
        f"expected exactly 1 template named {name!r}, got {resp['LaunchTemplates']!r}"
    )
    info = resp["LaunchTemplates"][0]
    assert info["LaunchTemplateId"] == lt_id, (
        f"expected id {lt_id!r}, got {info['LaunchTemplateId']!r}"
    )
    assert info["LaunchTemplateName"] == name, (
        f"expected name {name!r}, got {info['LaunchTemplateName']!r}"
    )
    assert info["LatestVersionNumber"] == 1, (
        f"expected LatestVersionNumber 1, got {info['LatestVersionNumber']!r}"
    )
    assert info["DefaultVersionNumber"] == 1, (
        f"expected DefaultVersionNumber 1, got {info['DefaultVersionNumber']!r}"
    )
    want_tags = _tag_map(sent_tags)
    assert _tag_map(info.get("Tags", [])) == want_tags, (
        f"describe-by-name Tags: expected {want_tags!r}, got {info.get('Tags')!r}"
    )

    resp_by_id = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])
    by_id_name = resp_by_id["LaunchTemplates"][0]["LaunchTemplateName"]
    assert by_id_name == name, f"describe-by-id for {lt_id!r} returned name {by_id_name!r}, expected {name!r}"
    want = (lt_id, name, 1, 1, want_tags)
    by_id = [_summary(t) for t in resp_by_id["LaunchTemplates"]]
    assert by_id == [want], f"describe-by-id for {lt_id!r}: expected [{want!r}], got {by_id!r}"

    # The tag key is unique to this run, so the filter matches exactly this template.
    by_tag_key = ec2.describe_launch_templates(
        Filters=[{"Name": f"tag:{tag_key}", "Values": [tag_value]}]
    )["LaunchTemplates"]
    got = [_summary(t) for t in by_tag_key]
    assert got == [want], f"tag:{tag_key}={tag_value!r} filter: expected [{want!r}], got {got!r}"
    unmatched = ec2.describe_launch_templates(
        Filters=[{"Name": f"tag:{tag_key}", "Values": [tag_value + "-other"]}]
    )["LaunchTemplates"]
    assert unmatched == [], f"tag:{tag_key} filter on another value must match nothing, got {unmatched!r}"

    # EC2 validates the id before any lookup, so a hex-looking fabricated id is Malformed,
    # not NotFound.
    bogus_id = "lt-0123456789abcdef0"
    code, message = _error(lambda: ec2.describe_launch_templates(LaunchTemplateIds=[bogus_id]))
    assert code == "InvalidLaunchTemplateId.Malformed", f"expected Malformed, got {code!r}"
    expected_message = f"The following launch template ids are malformed: {bogus_id}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _tag_map(tags_list) -> dict:
    return {t["Key"]: t["Value"] for t in tags_list}


def _summary(template) -> tuple:
    return (
        template["LaunchTemplateId"],
        template["LaunchTemplateName"],
        template["DefaultVersionNumber"],
        template["LatestVersionNumber"],
        _tag_map(template.get("Tags", [])),
    )


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean gone."""
    from botocore.exceptions import ClientError

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
