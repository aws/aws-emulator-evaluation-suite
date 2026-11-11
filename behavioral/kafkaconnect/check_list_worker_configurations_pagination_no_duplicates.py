"""list-worker-configurations-pagination-no-duplicates."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "list-worker-configurations-pagination-no-duplicates"
GROUP = "listing"
SERVICES = ["kafkaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListWorkerConfigurations with maxResults=1 eventually surfaces every created
    configuration exactly once, following nextToken to the end."""
    kc = ctx.client("kafkaconnect")

    prefix = ctx.unique_name("sim2real-kc-page-")
    props = base64.b64encode(
        b"key.converter=org.apache.kafka.connect.storage.StringConverter\n"
        b"value.converter=org.apache.kafka.connect.storage.StringConverter\n"
    ).decode()
    created_names = set()
    for i in range(3):
        name = f"{prefix}{i}"
        wc_arn = kc.create_worker_configuration(
            name=name, propertiesFileContent=props, tags={"Team": "streaming"}
        )["workerConfigurationArn"]
        ctx.on_cleanup(lambda arn=wc_arn: kc.delete_worker_configuration(workerConfigurationArn=arn))
        created_names.add(name)

    seen: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"namePrefix": prefix, "maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = kc.list_worker_configurations(**kwargs)
        for wc in page["workerConfigurations"]:
            seen.append(wc["name"])
        pages += 1
        next_token = page.get("nextToken")
        if not next_token or pages > 20:
            break

    assert pages >= 3, pages
    assert set(seen) == created_names, (set(seen), created_names)
    assert len(seen) == len(set(seen)), seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
