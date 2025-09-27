import os
import json
import boto3
import hmac
import uuid
import datetime
import logging
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

dynamodb = boto3.resource('dynamodb')
CONFIG_SK = "CONFIG"
scheduler_client = boto3.client('scheduler')

def lambda_handler(event, context):
    try:
        table_name = os.environ["DYNAMODB_TABLE_NAME"]
        http_method = event.get("httpMethod", "GET")
        logger.info(f"Lambda triggered with httpMethod={http_method}")
        if http_method == "GET":
            return get_salt_for_secret(event, table_name)
        elif http_method == "POST":
            return verify_and_activate_process(event, table_name)
        else:
            logger.warning(f"Method {http_method} not allowed.")
            return _method_not_allowed()
    except Exception as e:
        logger.error(f"Unhandled exception in lambda_handler: {e}")
        return _internal_error("Internal Server Error.")

def _get_secret_config(table_name, secret_id, projection=None):
    """Fetch the CONFIG item for a given secretId from DynamoDB, with optional projection."""
    table = dynamodb.Table(table_name)
    pk = f"SECRET#{secret_id}"
    try:
        kwargs = {"Key": {"PK": pk, "SK": CONFIG_SK}}
        if projection:
            kwargs["ProjectionExpression"] = projection
        response = table.get_item(**kwargs)
        logger.info(f"DynamoDB get_item for secretId projection={projection} result_found={bool(response.get('Item'))}")
    except ClientError as e:
        logger.error(f"DynamoDB error on get_item: {e}")
        raise Exception(f"DynamoDB error: {e}")
    return response.get("Item")

def _format_response(status_code, body_dict):
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(body_dict),
    }

def _unauthorized():
    return _format_response(401, {"message": "Unauthorized."})

def _conflict():
    return _format_response(409, {"message": "The recovery process for this secret is already active or has ended."})

def _bad_request(msg):
    return _format_response(400, {"message": msg})

def _method_not_allowed():
    return _format_response(405, {"message": "Method Not Allowed."})

def _internal_error(msg):
    return _format_response(500, {"message": msg})

def _update_process_status_and_token(table_name, secret_id, cancellation_token):
    table = dynamodb.Table(table_name)
    try:
        table.update_item(
            Key={"PK": f"SECRET#{secret_id}", "SK": CONFIG_SK},
            UpdateExpression="SET processStatus = :new_status, cancellation_token = :token",
            ConditionExpression="processStatus = :initial",
            ExpressionAttributeValues={
                ":new_status": "ACTIVATION_PENDING",
                ":initial": "INITIAL",
                ":token": cancellation_token
            }
        )
        logger.info(f"Updated processStatus to ACTIVATION_PENDING for secretId {secret_id}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning(f"ConditionalCheckFailedException on update_item for secretId {secret_id}")
            return False
        logger.error(f"DynamoDB error on update_item: {e}")
        raise
    return True

# TODO: Implement a scheduler to send emails/SMS every N configurable time interval.
def _send_activation_email(to_address, cancellation_token):
    ses_client = boto3.client('ses')
    sender = os.getenv("SENDER_EMAIL_ADDRESS")
    if not sender:
        logger.warning("SENDER_EMAIL_ADDRESS not configured; skipping email send")
        return
    subject = "Security Alert: A recovery process for your secret has been started in Posterit-E"
    cancel_url = f"https://posterite.run.place/cancel?token={cancellation_token}"
    body = (
        f"Hello,\n\nA recovery process for your secret in Posterit-E has been started. "
        f"If you did NOT authorize this process, you can cancel it immediately using the following secure link:\n\n"
        f"{cancel_url}\n\n"
        f"If you recognize this action, you can ignore this message.\n\n"
        f"Best regards,\nThe Posterit-E Team"
    )
    try:
        ses_client.send_email(
            Source=sender,
            Destination={"ToAddresses": [to_address]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": body, "Charset": "UTF-8"}}
            }
        )
        logger.info(f"Activation email sent to owner for secretId (token hidden)")
    except ClientError as e:
        logger.error(f"Failed to send activation email to owner: {e}")

def get_salt_for_secret(event, table_name):
    """Handles the GET /activation/{secretId} use case: returns the saltCr for the given secretId."""
    secret_id = event.get("pathParameters", {}).get("secretId")
    logger.info("GET /activation/{secretId} called")
    if not secret_id:
        logger.warning("Missing secretId in pathParameters.")
        return _bad_request("Missing secretId in path.")
    item = _get_secret_config(table_name, secret_id, projection="saltCr")
    if not item or not item.get("saltCr"):
        logger.warning(f"saltCr not found for secretId {secret_id}")
        return _unauthorized()
    logger.info(f"saltCr found for secretId {secret_id}")
    return _format_response(200, {"saltCr": item["saltCr"]})

def _schedule_secret_release(secret_id, grace_period_seconds):
    logger.info(f"Scheduling secret release for secretId {secret_id} with grace_period_seconds={grace_period_seconds}")
    if not isinstance(grace_period_seconds, int):
        try:
            grace_period_seconds = int(grace_period_seconds)
        except Exception:
            logger.error(f"gracePeriodSeconds invalid for secretId {secret_id}: {grace_period_seconds}")
            raise ValueError("The gracePeriodSeconds attribute is invalid or not present.")
    now = datetime.datetime.utcnow()
    release_time = now + datetime.timedelta(seconds=grace_period_seconds)
    schedule_expression = f"at({release_time.strftime('%Y-%m-%dT%H:%M:%S')})"
    release_lambda_arn = os.environ["RELEASE_LAMBDA_ARN"]
    scheduler_role_arn = os.environ["SCHEDULER_ROLE_ARN"]
    schedule_name = f"posterit-e-release-{secret_id}"
    try:
        scheduler_client.create_schedule(
            Name=schedule_name,
            ScheduleExpression=schedule_expression,
            ActionAfterCompletion='DELETE',
            Target={
                "Arn": release_lambda_arn,
                "RoleArn": scheduler_role_arn,
                "Input": json.dumps({"secretId": secret_id})
            },
            FlexibleTimeWindow={"Mode": "OFF"}
        )
        logger.info(f"EventBridge Scheduler create_schedule success for secretId {secret_id} at {schedule_expression}")
    except ClientError as e:
        logger.error(f"Failed to schedule secret release for secretId {secret_id}: {e}")
        raise

def verify_and_activate_process(event, table_name):
    logger.info("POST /activation called.")
    try:
        body = json.loads(event.get("body", "{}"))
    except Exception:
        logger.error("Invalid JSON body in POST /activation.")
        return _bad_request("Invalid JSON body.")

    secret_id = body.get("secretId")
    client_hash = body.get("clientHash")
    if not secret_id or not client_hash:
        logger.warning("Missing secretId or clientHash in request body.")
        return _bad_request("Missing secretId or clientHash in request body.")

    item = _get_secret_config(table_name, secret_id, projection="passwordHashCr,processStatus,titularAlertContact,gracePeriodSeconds")
    if not item or not item.get("passwordHashCr"):
        logger.warning(f"passwordHashCr not found for secretId {secret_id}")
        return _unauthorized()
    if item.get("processStatus") != "INITIAL":
        logger.warning(f"processStatus is not INITIAL for secretId {secret_id}")
        return _conflict()

    stored_hash = item["passwordHashCr"]
    if not hmac.compare_digest(str(client_hash), str(stored_hash)):
        logger.warning(f"Hash mismatch for secretId {secret_id}")
        return _unauthorized()

    cancellation_token = str(uuid.uuid4())
    if not _update_process_status_and_token(table_name, secret_id, cancellation_token):
        logger.warning(f"Could not update process status for secretId {secret_id}")
        return _conflict()

    titular_email = item.get("titularAlertContact")
    if titular_email:
        _send_activation_email(titular_email, cancellation_token)
    else:
        logger.warning(f"Owner email not found for the secretId {secret_id}.")

    grace_period = item.get("gracePeriodSeconds")
    try:
        _schedule_secret_release(secret_id, grace_period)
    except Exception as e:
        logger.error(f"Could not schedule secret release for secretId {secret_id}: {e}")
        return _internal_error("Could not schedule secret release.")

    logger.info(f"Activation process started for secretId {secret_id}. Owner notified and release scheduled.")
    return _format_response(200, {"message": "Activation process started. The Owner has been notified and the grace period has begun."})
