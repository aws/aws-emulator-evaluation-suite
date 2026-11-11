"""address-list-deletion-orphans-its-import-job."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "address-list-deletion-orphans-its-import-job"
GROUP = 'address-list-import-jobs'
SERVICES = ['mailmanager']


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an address list leaves its never-started import job orphaned: a
    later Get or List against it is rejected, naming the address list, not the job.
    """
    mm = ctx.client("mailmanager")
    al_id = mm.create_address_list(
        AddressListName=ctx.unique_name("sim2real-behav-mm-al-")
    )["AddressListId"]
    ctx.on_cleanup(lambda: mm.delete_address_list(AddressListId=al_id))

    job_id = mm.create_address_list_import_job(
        AddressListId=al_id,
        Name=ctx.unique_name("sim2real-behav-mm-job-"),
        ImportDataFormat={"ImportDataType": "CSV"},
    )["JobId"]

    # Positive control: before deletion, the job is readable and CREATED.
    before = mm.get_address_list_import_job(JobId=job_id)
    assert before["Status"] == "CREATED", f"expected CREATED before deletion, got {before['Status']!r}"

    mm.delete_address_list(AddressListId=al_id)

    expected_message = f"Could not find AddressList with id {al_id}"
    code, message = _error(lambda: mm.get_address_list_import_job(JobId=job_id))
    assert code == "ResourceNotFoundException", f"GetAddressListImportJob gave {code!r}"
    assert message == expected_message, f"unexpected message {message!r}"

    code, message = _error(lambda: mm.list_address_list_import_jobs(AddressListId=al_id))
    assert code == "ResourceNotFoundException", f"ListAddressListImportJobs gave {code!r}"
    assert message == expected_message, f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
