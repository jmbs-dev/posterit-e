import os
import json
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
import logging

# === Constants ===
CONFIG_SORT_KEY = "CONFIG"
TOKEN_CANCEL_SORT_KEY = "TOKEN#CANCEL"
TOKEN_INDEX_NAME = "TokenIndex"
EVENTBRIDGE_SCHEDULE_PREFIX = "posterit-e-release-"
DYNAMODB_TABLE_NAME = os.environ.get('DYNAMODB_TABLE_NAME')
EVENTBRIDGE_ARN = os.environ.get('EVENTBRIDGE_ARN')
SES_IDENTITY_ARN = os.environ.get('SESIdentityArn', 'noreply@posterite.app')

STATUS_ACTIVATION_PENDING = "ACTIVATION_PENDING"
STATUS_CANCELLED = "CANCELLED"

HTTP_STATUS_OK = 200
HTTP_STATUS_BAD_REQUEST = 400
HTTP_STATUS_UNAUTHORIZED = 401
HTTP_STATUS_NOT_FOUND = 404
HTTP_STATUS_CONFLICT = 409
HTTP_STATUS_INTERNAL_ERROR = 500

MSG_MISSING_TOKEN = "Missing cancellation token."
MSG_INVALID_TOKEN = "Invalid or expired cancellation token."
MSG_SECRET_NOT_FOUND = "Secret not found."
MSG_INVALID_STATE = "Process cannot be cancelled in its current state."
MSG_ALREADY_CANCELLED = "Process already cancelled or not pending."
MSG_INTERNAL_ERROR = "Internal error during cancellation."
MSG_SERVER_ERROR = "Internal server error."
MSG_CANCELLED_SUCCESS = "Process cancelled successfully."

RELEASE_TOKEN_SORT_KEY = "TOKEN#RELEASE"

# === AWS Clients ===
session = boto3.session.Session()
dynamodb_resource = session.resource('dynamodb')
dynamodb_client = session.client('dynamodb')
scheduler_client = session.client('scheduler')
ses_client = session.client('ses')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    AWS Lambda entry point for cancellation requests.
    Args:
        event (dict): Lambda event payload.
        context (LambdaContext): Lambda context object.
    Returns:
        dict: API Gateway-compatible response.
    """
    try:
        request_body = _parse_request_body(event)
        cancellation_token = _extract_cancellation_token(request_body)
        if not cancellation_token:
            return _build_response(HTTP_STATUS_BAD_REQUEST, MSG_MISSING_TOKEN)

        token_item = _get_token_item_by_value(cancellation_token)
        if not token_item:
            return _build_response(HTTP_STATUS_UNAUTHORIZED, MSG_INVALID_TOKEN)

        partition_key = token_item['PK']
        secret_id = partition_key.replace('SECRET#', '')
        config_item = _get_config_item(partition_key)
        if not config_item:
            return _build_response(HTTP_STATUS_NOT_FOUND, MSG_SECRET_NOT_FOUND)

        titular_email = config_item.get('titularAlertContact')
        process_status = config_item.get('processStatus')
        if process_status != STATUS_ACTIVATION_PENDING:
            return _build_response(HTTP_STATUS_CONFLICT, MSG_INVALID_STATE)

        transaction_success = _cancel_process_transaction(partition_key)
        if transaction_success == 'conflict':
            return _build_response(HTTP_STATUS_CONFLICT, MSG_ALREADY_CANCELLED)
        elif transaction_success == 'error':
            return _build_response(HTTP_STATUS_INTERNAL_ERROR, MSG_INTERNAL_ERROR)

        _delete_eventbridge_schedule(secret_id)
        if titular_email:
            _send_cancellation_email(titular_email, secret_id)

        return _build_response(HTTP_STATUS_OK, MSG_CANCELLED_SUCCESS)
    except Exception as exc:
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return _build_response(HTTP_STATUS_INTERNAL_ERROR, MSG_SERVER_ERROR)

def _parse_request_body(event):
    """
    Parses the request body from the event.
    Args:
        event (dict): Lambda event payload.
    Returns:
        dict: Parsed JSON body.
    """
    try:
        return json.loads(event.get('body', '{}'))
    except Exception:
        return {}

def _extract_cancellation_token(body):
    """
    Extracts the cancellation token from the request body.
    Args:
        body (dict): Parsed request body.
    Returns:
        str or None: Cancellation token value.
    """
    return body.get('token') or body.get('cancellation_token')

def _get_token_item_by_value(token_value):
    """
    Queries DynamoDB GSI to find the cancellation token item.
    Args:
        token_value (str): The cancellation token value.
    Returns:
        dict or None: Token item if found, else None.
    """
    table = dynamodb_resource.Table(DYNAMODB_TABLE_NAME)
    try:
        response = table.query(
            IndexName=TOKEN_INDEX_NAME,
            KeyConditionExpression=Key('tokenValue').eq(token_value)
        )
        for config_item in response.get('Items', []):
            if config_item.get('SK') == TOKEN_CANCEL_SORT_KEY:
                return config_item
        return None
    except ClientError as exc:
        logger.error(f"DynamoDB GSI query error: {exc}")
        return None

def _get_config_item(partition_key):
    """
    Retrieves the CONFIG item for the secret.
    Args:
        partition_key (str): The partition key for the secret.
    Returns:
        dict or None: CONFIG item if found, else None.
    """
    table = dynamodb_resource.Table(DYNAMODB_TABLE_NAME)
    try:
        response = table.get_item(Key={'PK': partition_key, 'SK': CONFIG_SORT_KEY})
        return response.get('Item')
    except ClientError as exc:
        logger.error(f"DynamoDB get_item error: {exc}")
        return None

def _cancel_process_transaction(partition_key):
    """
    Performs an atomic transaction to cancel the process and delete the token and release token.
    Args:
        partition_key (str): The partition key for the secret.
    Returns:
        str: 'success', 'conflict', or 'error'
    """
    try:
        transact_items = [
            {
                'Update': {
                    'TableName': DYNAMODB_TABLE_NAME,
                    'Key': {'PK': {'S': partition_key}, 'SK': {'S': CONFIG_SORT_KEY}},
                    'UpdateExpression': 'SET processStatus = :cancelled REMOVE gracePeriodExpiresAt',
                    'ConditionExpression': 'processStatus = :pending',
                    'ExpressionAttributeValues': {
                        ':cancelled': {'S': STATUS_CANCELLED},
                        ':pending': {'S': STATUS_ACTIVATION_PENDING}
                    }
                }
            },
            {
                'Delete': {
                    'TableName': DYNAMODB_TABLE_NAME,
                    'Key': {'PK': {'S': partition_key}, 'SK': {'S': TOKEN_CANCEL_SORT_KEY}}
                }
            },
            {
                'Delete': {
                    'TableName': DYNAMODB_TABLE_NAME,
                    'Key': {'PK': {'S': partition_key}, 'SK': {'S': RELEASE_TOKEN_SORT_KEY}}
                }
            }
        ]
        dynamodb_client.transact_write_items(TransactItems=transact_items)
        return 'success'
    except Exception as exc:
        error_code = None
        if hasattr(exc, 'response') and isinstance(exc.response, dict):
            error_code = exc.response.get('Error', {}).get('Code')
        if error_code == 'ConditionalCheckFailedException':
            return 'conflict'
        logger.error(f"DynamoDB transaction error: {exc}")
        return 'error'

def _delete_eventbridge_schedule(secret_id):
    """
    Deletes the scheduled EventBridge Scheduler schedule for secret release.
    Args:
        secret_id (str): The secret identifier.
    """
    schedule_name = f"{EVENTBRIDGE_SCHEDULE_PREFIX}{secret_id}"
    try:
        scheduler_client.delete_schedule(Name=schedule_name, GroupName='default')
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            logger.error(f"Scheduler cleanup error: {exc}")
    except Exception as exc:
        logger.error(f"General Scheduler cleanup error: {exc}")

def _send_cancellation_email(email, secret_id):
    """
    Sends a cancellation confirmation email to the titular.
    Args:
        email (str): Recipient email address.
        secret_id (str): The secret identifier.
    """
    subject = "Posterit-E: Cancelación de proceso de recuperación"
    body = (
        "El proceso de recuperación de tu secreto ha sido cancelado exitosamente.\n\n"
        "Si no solicitaste esta acción, por favor ignora este mensaje."
    )
    try:
        ses_client.send_email(
            Source=SES_IDENTITY_ARN,
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body}}
            }
        )
    except ClientError as exc:
        logger.error(f"SES send_email error: {exc}")

def _build_response(status_code, message):
    """
    Builds an API Gateway-compatible response.
    Args:
        status_code (int): HTTP status code.
        message (str): Message to include in the response body.
    Returns:
        dict: API Gateway response.
    """
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "POST,OPTIONS"
        },
        "body": json.dumps({"message": message})
    }
