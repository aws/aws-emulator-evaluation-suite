"""create-target-group-malformed-health-check-path-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-target-group-malformed-health-check-path-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetGroup rejects an HTTP health-check path that is missing its required leading
    slash with a ValidationError and creates NO target group at all, while the same request
    with a well-formed '/...' path succeeds."""
    elbv2 = ctx.client("elbv2")
    vpc_id = _create_vpc_only(ctx)

    bad_name = ctx.unique_name("sim2real-tgbad-")
    code, message = _error(
        lambda: elbv2.create_target_group(
            Name=bad_name,
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
            TargetType="ip",
            HealthCheckProtocol="HTTP",
            HealthCheckPath="missing-leading-slash",
        )
    )
    assert code == "ValidationError", code
    expected = (
        "Health check path 'missing-leading-slash' must begin with a '/' character "
        "and can only contain printable ASCII characters, without spaces"
    )
    assert message == expected, f"MSG={message!r}"

    # effect-absent: the rejected create must not have left a target group behind
    not_found_code, not_found_message = _error(
        lambda: elbv2.describe_target_groups(Names=[bad_name])
    )
    assert not_found_code == "TargetGroupNotFound", not_found_code
    assert not_found_message == "One or more target groups not found", f"MSG={not_found_message!r}"

    # positive control: a well-formed path on an otherwise-identical request succeeds
    good_name = ctx.unique_name("sim2real-tgok-")
    tg = elbv2.create_target_group(
        Name=good_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/healthz",
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))

    described = elbv2.describe_target_groups(Names=[good_name])["TargetGroups"][0]
    assert described["HealthCheckPath"] == "/healthz", described

    # deletes prove gone and unusable: an independent read 404s, and a mutation on the
    # dead arn also fails with the same specific not-found code
    elbv2.delete_target_group(TargetGroupArn=tg_arn)
    gone_code, gone_message = _error(lambda: elbv2.describe_target_groups(Names=[good_name]))
    assert gone_code == "TargetGroupNotFound", gone_code
    assert gone_message == "One or more target groups not found", f"MSG={gone_message!r}"
    mutate_code, mutate_message = _error(
        lambda: elbv2.modify_target_group(TargetGroupArn=tg_arn, HealthCheckPath="/other")
    )
    assert mutate_code == "TargetGroupNotFound", mutate_code
    assert mutate_message == f"Target groups '{tg_arn}' not found", f"MSG={mutate_message!r}"


def _error(fn) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as err:
        if "NotFound" not in err.response.get("Error", {}).get("Code", ""):
            raise


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_only(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-elbv2-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16", TagSpecifications=[_tag_spec("vpc", name)]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
