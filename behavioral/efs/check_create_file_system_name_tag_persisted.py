"""create-file-system-name-tag-persisted."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-file-system-name-tag-persisted"
GROUP = "data-plane"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A 'Name' tag supplied at CreateFileSystem is surfaced as the FileSystemDescription.Name field."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    name_value = ctx.unique_name("sim2real-efs-name-")
    created = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "Name", "Value": name_value}, {"Key": "Owner", "Value": "sim2real"}]
    )
    fs_id = created["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))

    assert created["Name"] == name_value, f"CreateFileSystem response Name expected {name_value!r}, got {created.get('Name')!r}"

    described = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]
    assert described["Name"] == name_value, (
        f"DescribeFileSystems Name expected {name_value!r}, got {described.get('Name')!r}"
    )

    tags = {t["Key"]: t["Value"] for t in efs.describe_tags(FileSystemId=fs_id)["Tags"]}
    assert tags["Name"] == name_value, f"DescribeTags Name expected {name_value!r}, got {tags.get('Name')!r}"
    assert tags["Owner"] == "sim2real", f"DescribeTags Owner expected 'sim2real', got {tags.get('Owner')!r}"


def _delete_fs_best_effort(efs, fs_id):
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            state = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "FileSystemNotFound":
                raise
            return
        if state == "available":
            break
        time.sleep(3.0)
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
