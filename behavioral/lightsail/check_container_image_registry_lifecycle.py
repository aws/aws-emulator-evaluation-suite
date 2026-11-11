"""container-image-registry-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "container-image-registry-lifecycle"
GROUP = "overly-permissive"
SERVICES = ["lightsail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A new container service has no images; RegisterContainerImage with a never-pushed digest raises
    NotFoundException, DeleteContainerImage on a nonexistent service raises InvalidInputException (each with
    its exact message), and no image is registered."""
    ls = ctx.client("lightsail")
    service_name = ctx.unique_name("sim2real-ls-cs-")

    ls.create_container_service(
        serviceName=service_name,
        power="nano",
        scale=1,
        tags=[{"key": "Name", "value": service_name}],
    )
    ctx.on_cleanup(lambda: _delete_service(ls, service_name))

    images = ls.get_container_images(serviceName=service_name)["containerImages"]
    assert images == [], f"freshly created container service already has images: {images!r}"

    digest = "sha256:" + "a" * 64
    code, message = _error(
        lambda: ls.register_container_image(serviceName=service_name, label="roundtrip", digest=digest)
    )
    assert code == "NotFoundException", f"unexpected code registering an unpushed image digest: {code!r}"
    assert message == f'Image with digest "{digest}" not found.', f"unexpected message: {message!r}"

    missing_service_name = ctx.unique_name("sim2real-ls-cs-missing-")
    code, message = _error(
        lambda: ls.delete_container_image(
            serviceName=missing_service_name, image=f":{missing_service_name}.roundtrip.1"
        )
    )
    assert code == "InvalidInputException", f"unexpected code deleting from a nonexistent service: {code!r}"
    assert message == f'Service "{missing_service_name}" does not exist.', f"unexpected message: {message!r}"

    # A never-registered image reference on an existing service deletes as a no-op; any
    # ClientError here propagates and fails the check.
    fake_image_ref = f":{service_name}.roundtrip.1"
    ls.delete_container_image(serviceName=service_name, image=fake_image_ref)

    images_after = ls.get_container_images(serviceName=service_name)["containerImages"]
    assert images_after == [], "container images appeared despite no successful registration"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target accepting
    what real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _delete_service(ls, service_name, timeout_s=600.0, interval_s=15.0):
    """DeleteContainerService refuses while the service is in a transition state such as
    PENDING; retry until it is accepted or the service is gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ls.delete_container_service(serviceName=service_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            if e.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
