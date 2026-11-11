"""delete-instance-profile."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-instance-profile"
GROUP = 'instance_profiles'
SERVICES = ['iam']

ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteInstanceProfile removes it; the id reads gone, rejects a mutation, and is reusable."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(InstanceProfileName=name, Path="/")
    live = {"value": True}
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name) if live["value"] else None)

    iam.delete_instance_profile(InstanceProfileName=name)
    live["value"] = False

    code, message = _error_code(lambda: iam.get_instance_profile(InstanceProfileName=name))
    assert code == ERR_NO_SUCH_ENTITY, f"expected {ERR_NO_SUCH_ENTITY} on get after delete, got {code!r}"
    assert message == f"Instance Profile {name} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {message!r}"
    )

    mutate_code, mutate_message = _error_code(
        lambda: iam.tag_instance_profile(
            InstanceProfileName=name, Tags=[{"Key": "sim2real-behav-probe", "Value": "post-delete"}]
        )
    )
    assert mutate_code == ERR_NO_SUCH_ENTITY, (
        f"expected {ERR_NO_SUCH_ENTITY} tagging a deleted profile, got {mutate_code!r}"
    )
    assert mutate_message == f"Instance Profile {name} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {mutate_message!r}"
    )

    iam.create_instance_profile(InstanceProfileName=name, Path="/")
    live["value"] = True
    profiles = [p["InstanceProfileName"] for p in _listed(iam, "list_instance_profiles", "InstanceProfiles")]
    assert name in profiles, "freed instance profile name did not become reusable"


def _listed(iam, operation, key):
    """Every item an IAM listing returns, across all pages."""
    return [item for page in iam.get_paginator(operation).paginate() for item in page[key]]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
