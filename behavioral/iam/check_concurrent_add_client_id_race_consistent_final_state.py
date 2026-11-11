"""concurrent-add-client-id-race-consistent-final-state."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-add-client-id-race-consistent-final-state"
GROUP = "concurrency"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AddClientIDToOpenIDConnectProvider calls with distinct IDs lose no update:
    after retrying contention losers, ClientIDList holds every added ID exactly once."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-oidcaddrace-")
    url = f"https://{name}.example.com"
    thumbprint = "d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6"

    created = iam.create_open_id_connect_provider(
        Url=url,
        ThumbprintList=[thumbprint],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))

    client_ids = [f"sim2real-race-aud-{i}" for i in range(6)]
    barrier = threading.Barrier(len(client_ids))
    outcomes: list[tuple[str, str, str]] = [("", "", "")] * len(client_ids)

    def racer(i: int) -> None:
        cid = client_ids[i]
        barrier.wait()
        try:
            iam.add_client_id_to_open_id_connect_provider(
                OpenIDConnectProviderArn=arn, ClientID=cid
            )
            outcomes[i] = ("ok", cid, "")
        except ClientError as exc:
            outcomes[i] = (exc.response["Error"]["Code"], cid, exc.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=len(client_ids)) as pool:
        list(pool.map(racer, range(len(client_ids))))

    # Any racer that lost contention for the shared ClientIDList (observed on real AWS
    # as ConcurrentModificationException, and occasionally as transient Throttling /
    # LimitExceededException under heavy simultaneous writes to the same object) must
    # retry -- a real client library would do the same -- and that retry must succeed.
    # Any other error is a genuine defect.
    retryable_codes = {
        "ConcurrentModificationException",
        "ConcurrentModification",
        "LimitExceededException",
        "LimitExceeded",
        "Throttling",
        "ThrottlingException",
        "ServiceFailureException",
        "ServiceFailure",
    }
    # The exact wording AWS returns for the contention refusal.
    worded = {"ConcurrentModification": "Too many operations are modifying this entity. Please try again later."}
    for status, cid, message in outcomes:
        if status != "ok":
            assert status in retryable_codes, (
                f"unexpected error code {status!r} adding client id {cid!r} under contention"
            )
            if status in worded:
                assert message == worded[status], (
                    f"{status} adding client id {cid!r}: message {message!r}, expected {worded[status]!r}"
                )
            last_exc = None
            for attempt in range(6):
                try:
                    iam.add_client_id_to_open_id_connect_provider(
                        OpenIDConnectProviderArn=arn, ClientID=cid
                    )
                    last_exc = None
                    break
                except ClientError as exc:
                    last_exc = exc
                    time.sleep(1.0 * (attempt + 1))
            assert last_exc is None, (
                f"retry of client id {cid!r} after contention kept failing: {last_exc}"
            )

    final_client_ids = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)["ClientIDList"]
    assert sorted(final_client_ids) == sorted(client_ids), (
        f"final ClientIDList {final_client_ids!r} does not contain exactly the "
        f"{len(client_ids)} distinct client IDs added under contention: {client_ids!r}"
    )
    assert len(final_client_ids) == len(set(final_client_ids)), (
        f"final ClientIDList contains duplicate entries: {final_client_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
