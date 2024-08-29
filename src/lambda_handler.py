"""AWS Lambda handler to disable inactive IAM users."""

# Standard Python Libraries
from datetime import datetime, timedelta, timezone
import logging
import os
from typing import Any, Dict, List, NamedTuple, Optional, Union

# Third-Party Libraries
import boto3

default_log_level = "INFO"
logger = logging.getLogger()
logger.setLevel(default_log_level)


class EventValidation(NamedTuple):
    """Named tuple to hold event validation information."""

    errors: List[str]
    event: Dict[str, Any]
    valid: bool


def failed_task(result: dict[str, Any], error_msg: str) -> None:
    """Update a given result because of a failure during processing."""
    result["success"] = False
    result["error_message"] = error_msg


def task_default(event):
    """Provide a result if no valid task was provided."""
    result = {}
    error_msg = 'Provided task "%s" is not supported.'

    task = event.get("task", None)
    logging.error(error_msg, task)
    failed_task(result, error_msg % task)

    return result


def validate_event_data(event: Dict[str, Any]) -> EventValidation:
    """Validate the event data and return a tuple containing the validated event, a boolean result (True if valid, False if invalid), and a list of error message strings."""
    result = True
    errors = []

    # Check that expiration_days can be interpreted as a strictly positive
    # integer.
    if "expiration_days" not in event:
        errors.append('Missing required key "expiration_days" in event.')
    elif not event["expiration_days"]:
        errors.append('"account_ids" must be non-null.')
    else:
        try:
            tmp = int(event["expiration_days"])
            if tmp < 0:
                errors.append('"account_ids" must be a strictly positive integer.')
        except ValueError:
            errors.append('"account_ids" must be an integer.')

    if errors:
        result = False

    return EventValidation(errors, event, result)


def task_disable(event):
    """Iterate over users and disable any inactive access."""
    result: Dict[str, Union[Optional[str], bool]] = {"message": None, "success": True}

    # Validate all event data before going any further
    event_validation: EventValidation = validate_event_data(event)
    if not event_validation.valid:
        for e in event_validation.errors:
            logging.error(e)
        failed_task(result, " ".join(event_validation.errors))
        return result
    validated_event = event_validation.event

    # The number of days after which unused access is considered inactive.
    expiration_days: int = int(validated_event["expiration_days"])

    # Create an IAM client
    iam: boto3.client = boto3.client("iam")

    # Create a paginator for users
    user_paginator = iam.get_paginator("list_users")

    # Create an iterator from the paginator
    user_iterator = user_paginator.paginate()

    # Capture the current time and date
    now = datetime.now()
    too_old = timedelta(days=expiration_days)

    # Iterate over the users
    for user in user_iterator:
        user_name = user["UserName"]
        password_last_used = user["PasswordLastUsed"]

        logging.debug("Examining user %s's console access", user_name)

        if now - password_last_used > too_old:
            logging.info(
                "Disabling user %s's console access due to inactivity", user_name
            )
            # Disable the user's console access
            # iam.delete_login_profile(UserName=user_name)

        # Create a paginator for access keys
        access_key_paginator = iam.get_paginator("list_access_keys")

        # Create an iterator from the paginator
        access_key_iterator = access_key_paginator.paginate(UserName=user_name)

        logging.debug("Examining user %s's access keys", user_name)
        # Iterate over the access keys
        for access_key in access_key_iterator:
            access_key_id = access_key["AccessKeyId"]
            access_key_last_used = iam.get_access_key_last_used(
                AccessKeyId=access_key_id
            )

            logging.debug("Examining user %s's access key %s", user_name, access_key_id)

            if now - access_key_last_used > too_old:
                logging.info(
                    "Disabling user %s's access key %s due to inactivity",
                    user_name,
                    access_key_id,
                )
                # Make the access key inactive
                # iam.update_access_key(AccessKeyId=access_key_id, Status="Inactive", UserName=user_name)
    result["message"] = "Successfully disabled inactive IAM users."
    logging.info(result["message"])
    return result


def handler(event, context) -> dict[str, Optional[str]]:
    """Process the event and generate a response.

    The event should have a task member that is one of the supported tasks.

    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: The result of the action.
    """
    old_log_level = None
    response: dict[str, Optional[str]] = {"timestamp": str(datetime.now(timezone.utc))}

    # Update the logging level if necessary
    new_log_level = os.environ.get("log_level", default_log_level).upper()
    if not isinstance(logging.getLevelName(new_log_level), int):
        logging.warning(
            "Invalid logging level %s. Using %s instead.",
            new_log_level,
            default_log_level,
        )
        new_log_level = default_log_level
    if logging.getLogger().getEffectiveLevel() != logging.getLevelName(new_log_level):
        old_log_level = logging.getLogger().getEffectiveLevel()
        logging.getLogger().setLevel(new_log_level)

    task_name = f"task_{event.get('task')}"
    task = globals().get(task_name, task_default)

    result: dict[str, Any]
    if not callable(task):
        logging.error("Provided task is not a callable.")
        logging.error(task)
        result = task_default(event)
    else:
        result = task(event)
    response.update(result)

    if old_log_level is not None:
        logging.getLogger().setLevel(old_log_level)

    return response
