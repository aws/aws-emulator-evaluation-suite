"""instance-profile-tag-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-profile-tag-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Instance-profile tags list back after TagInstanceProfile; untag removes only the named key.
    After deletion, GetInstanceProfile and TagInstanceProfile both fail NoSuchEntity with
    AWS's exact message."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-instprof-")

    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(lambda: _gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=name)))

    _retry_until_success(
        lambda: iam.tag_instance_profile(
            InstanceProfileName=name,
            Tags=[
                {"Key": "Environment", "Value": "sim2real-test"},
                {"Key": "Owner", "Value": "behavioral-suite"},
            ],
        )
    )

    tags_map = _tagmap(iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"])
    assert tags_map.get("Environment") == "sim2real-test", (
        f"expected Environment=sim2real-test, got {tags_map}"
    )
    assert tags_map.get("Owner") == "behavioral-suite", (
        f"expected Owner=behavioral-suite, got {tags_map}"
    )

    iam.untag_instance_profile(InstanceProfileName=name, TagKeys=["Environment"])

    tags_after = _tagmap(iam.list_instance_profile_tags(InstanceProfileName=name)["Tags"])
    assert "Environment" not in tags_after, f"targeted key survived untag: {tags_after}"
    assert tags_after.get("Owner") == "behavioral-suite", (
        f"untouched key lost after untag: {tags_after}"
    )

    iam.delete_instance_profile(InstanceProfileName=name)
    code, message = _error(lambda: iam.get_instance_profile(InstanceProfileName=name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity reading a deleted instance profile, got {code}"
    expected_read = f"Instance Profile {name} cannot be found."
    assert message == expected_read, (
        f"GetInstanceProfile on the deleted profile must carry AWS's exact message "
        f"{expected_read!r}; got {message!r}"
    )
    mutate_code, mutate_message = _error(
        lambda: iam.tag_instance_profile(InstanceProfileName=name, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert mutate_code == "NoSuchEntity", (
        f"expected NoSuchEntity tagging a deleted instance profile, got {mutate_code}"
    )
    expected_mutate = f"Instance Profile {name} cannot be found."
    assert mutate_message == expected_mutate, (
        f"TagInstanceProfile on the deleted profile must carry AWS's exact message "
        f"{expected_mutate!r}; got {mutate_message!r}"
    )


def _tagmap(tags):
    return {t["Key"]: t["Value"] for t in tags}


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _retry_until_success(fn, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _gone_ok(fn):
    """Teardown-only: the body deletes this resource itself, so tolerate it already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
