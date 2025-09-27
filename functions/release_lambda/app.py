import os
import json
import boto3
import hmac
import uuid
import base64
import time
import logging
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

# Constants
CONFIG_SK = "CONFIG"
ENCRYPTED_PAYLOAD_SK = "ENCRYPTED_PAYLOAD"
TOKEN_TTL_SECONDS = int(os.environ.get('TOKEN_TTL_SECONDS', '300'))  # 5 minutes
OTP_TTL_SECONDS = int(os.environ.get('OTP_TTL_SECONDS', '600'))    # 10 minutes
BASE_URL = os.environ.get('BASE_URL', 'https://posterite.app')
SENDER_EMAIL_ADDRESS = os.environ.get('SENDER_EMAIL_ADDRESS')

# AWS clients
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')
ses_client = boto3.client('ses')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def lambda_handler(event, context):
    """
    Main Lambda handler for release_lambda.
    Routes the event to the correct flow based on the trigger source and HTTP method.
    Handles MFA initiation, MFA verification, and secure data release.
    """
    if event.get("source") == "aws.scheduler":
        return _initiate_mfa_verification(event)
    if event.get("httpMethod") == "POST" and event.get("path") == "/mfa/verify":
        return _handle_mfa_verify(event)
    if event.get("httpMethod") == "GET" and event.get("path", "").endswith("/data"):
        return _handle_data_release(event)
    return _format_response(404, {"message": "Not found."})


def _get_env(var, default=None):
    """
    Helper to get environment variables with an optional default value.
    Used for configuration and secrets management.
    """
    return os.environ.get(var, default)


def _format_response(status_code, body_dict):
    """
    Formats the HTTP response for API Gateway.
    Adds CORS headers and serializes the body to JSON.
    """
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(body_dict),
    }


def _get_secret_config(secret_id, projection=None):
    """
    Retrieves the CONFIG item for a given secretId from DynamoDB.
    Optionally allows projection of specific fields.
    Returns the item as a dict or None if not found.
    """
    table = dynamodb.Table(_get_env('DYNAMODB_TABLE_NAME'))
    pk = f"SECRET#{secret_id}"
    try:
        kwargs = {"Key": {"PK": pk, "SK": CONFIG_SK}}
        if projection:
            kwargs["ProjectionExpression"] = projection
        response = table.get_item(**kwargs)
    except ClientError as e:
        logger.error(f"DynamoDB get_item error: {e}")
        return None
    return response.get("Item")


def _update_secret_config_mfa(secret_id, otp, expires_at):
    """
    Atomically updates the CONFIG item in DynamoDB to set MFA_PENDING state,
    store the OTP and its expiration timestamp. Returns True if successful,
    False if the condition fails or an error occurs.
    """
    table = dynamodb.Table(_get_env('DYNAMODB_TABLE_NAME'))
    pk = f"SECRET#{secret_id}"
    try:
        table.update_item(
            Key={"PK": pk, "SK": CONFIG_SK},
            ConditionExpression="processStatus = :pending",
            UpdateExpression="SET processStatus = :mfa, otpCode = :otp, otpExpiresAt = :exp",
            ExpressionAttributeValues={
                ":pending": "ACTIVATION_PENDING",
                ":mfa": "MFA_PENDING",
                ":otp": otp,
                ":exp": expires_at
            }
        )
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return False
        logger.error(f"DynamoDB update_item error: {e}")
        return False


def _send_otp_email(contact, otp, expires_at):
    """
    Sends the OTP code to the beneficiary via SES email.
    The email includes the OTP and its expiration time.
    """
    expires_str = datetime.fromtimestamp(expires_at, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    subject = "Posterit-E: Código de verificación final"
    body = f"Su código de verificación para liberar el secreto es: {otp}. Este código expira el {expires_str}."
    try:
        ses_client.send_email(
            Source=SENDER_EMAIL_ADDRESS,
            Destination={"ToAddresses": [contact]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body}}
            }
        )
    except ClientError as e:
        logger.error(f"SES send_email error: {e}")


def _verify_otp(secret_id, otp_code):
    """
    Verifies the OTP code for a secret. If valid and not expired, creates a one-time access token,
    updates the process status, and sends the secure access link via email. Returns an API response.
    """
    table = dynamodb.Table(_get_env('DYNAMODB_TABLE_NAME'))
    config = _get_secret_config(secret_id)
    if not config:
        return _format_response(404, {"message": "Secret not found."})
    if config.get("processStatus") != "MFA_PENDING":
        return _format_response(409, {"message": "Invalid process status."})
    now = int(time.time())
    if now > int(config.get("otpExpiresAt", 0)):
        return _format_response(401, {"message": "OTP expired."})
    stored_otp = config.get("otpCode")
    if not stored_otp or not hmac.compare_digest(str(otp_code), str(stored_otp)):
        return _format_response(401, {"message": "Invalid OTP code."})
    # OTP valid: create access token
    access_token = str(uuid.uuid4())
    token_expires = now + TOKEN_TTL_SECONDS
    _create_access_token(secret_id, access_token, token_expires)
    # Update processStatus
    pk = f"SECRET#{secret_id}"
    table.update_item(
        Key={"PK": pk, "SK": CONFIG_SK},
        UpdateExpression="SET processStatus = :released REMOVE otpCode, otpExpiresAt",
        ExpressionAttributeValues={":released": "RELEASED"}
    )
    # Send release email
    contact = config.get("beneficiaryContact")
    _send_release_email(contact, secret_id, access_token)
    return _format_response(200, {"message": "Verificación exitosa. Recibirá un enlace seguro para acceder al secreto."})


def _create_access_token(secret_id, token, expires_at):
    """
    Creates a one-time access token item in DynamoDB for the secret.
    The token expires after TOKEN_TTL_SECONDS.
    """
    table = dynamodb.Table(_get_env('DYNAMODB_TABLE_NAME'))
    pk = f"SECRET#{secret_id}"
    sk = f"TOKEN#{token}"
    try:
        table.put_item(
            Item={
                "PK": pk,
                "SK": sk,
                "ttl": expires_at
            }
        )
    except ClientError as e:
        logger.error(f"DynamoDB put_item error: {e}")


def _send_release_email(contact, secret_id, token):
    """
    Sends the secure access link to the beneficiary via SES email.
    The link includes the secretId and one-time access token, and is valid for TOKEN_TTL_SECONDS.
    """
    link = f"{BASE_URL}/secrets/{secret_id}/data?token={token}"
    subject = "Posterit-E: Enlace seguro para acceder al secreto"
    body = f"Puede acceder a su secreto usando el siguiente enlace (válido por 5 minutos):\n{link}"
    try:
        ses_client.send_email(
            Source=SENDER_EMAIL_ADDRESS,
            Destination={"ToAddresses": [contact]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body}}
            }
        )
    except ClientError as e:
        logger.error(f"SES send_email error: {e}")


def _consume_token_and_get_payload(secret_id, token):
    """
    Atomically consumes (deletes) the access token from DynamoDB and retrieves the encrypted payload.
    Downloads the encrypted secret from S3 and returns all cryptographic artifacts in the response.
    """
    table = dynamodb.Table(_get_env('DYNAMODB_TABLE_NAME'))
    pk = f"SECRET#{secret_id}"
    sk = f"TOKEN#{token}"
    try:
        response = table.delete_item(
            Key={"PK": pk, "SK": sk},
            ReturnValues="ALL_OLD"
        )
        if "Attributes" not in response:
            return _format_response(401, {"message": "Invalid or expired token."})
    except ClientError as e:
        logger.error(f"DynamoDB delete_item error: {e}")
        return _format_response(500, {"message": "Internal error."})
    # Get encrypted payload
    payload_item = _get_encrypted_payload(secret_id)
    if not payload_item:
        return _format_response(404, {"message": "Encrypted payload not found."})
    encrypted_dek = payload_item.get("encryptedDek")
    salt_kek = payload_item.get("saltKek")
    s3_key = payload_item.get("s3ObjectKey")
    if not (encrypted_dek and salt_kek and s3_key):
        return _format_response(500, {"message": "Incomplete payload metadata."})
    # Download encrypted secret from S3
    try:
        s3_obj = s3_client.get_object(Bucket=_get_env('S3_BUCKET_NAME'), Key=s3_key)
        encrypted_secret_bytes = s3_obj["Body"].read()
        encrypted_secret_b64 = base64.b64encode(encrypted_secret_bytes).decode()
    except ClientError as e:
        logger.error(f"S3 get_object error: {e}")
        return _format_response(500, {"message": "Error retrieving encrypted secret."})
    payload = {
        "encryptedSecret": encrypted_secret_b64,
        "encryptedDek": encrypted_dek,
        "saltKek": salt_kek
    }
    return _format_response(200, payload)


def _get_encrypted_payload(secret_id):
    """
    Retrieves the ENCRYPTED_PAYLOAD item for a given secretId from DynamoDB.
    Returns the item as a dict or None if not found.
    """
    table = dynamodb.Table(_get_env('DYNAMODB_TABLE_NAME'))
    pk = f"SECRET#{secret_id}"
    try:
        response = table.get_item(Key={"PK": pk, "SK": ENCRYPTED_PAYLOAD_SK})
    except ClientError as e:
        logger.error(f"DynamoDB get_item error: {e}")
        return None
    return response.get("Item")


def _initiate_mfa_verification(event):
    """
    Handles the EventBridge Scheduler trigger for MFA initiation.
    This flow is responsible for:
    - Validating that the secret is in ACTIVATION_PENDING state.
    - Generating a secure OTP code and its expiration timestamp.
    - Atomically updating the secret's config in DynamoDB to MFA_PENDING, storing the OTP and expiration.
    - Sending the OTP code to the beneficiary via SES email.
    - No HTTP response is returned (silent completion for scheduler).
    """
    secret_id = event.get("secretId")
    if not secret_id:
        return
    config = _get_secret_config(secret_id)
    if not config:
        return
    if config.get("processStatus") != "ACTIVATION_PENDING":
        return
    otp = str(uuid.uuid4().int)[-6:]
    expires_at = int(time.time()) + OTP_TTL_SECONDS
    updated = _update_secret_config_mfa(secret_id, otp, expires_at)
    if not updated:
        return
    contact = config.get("beneficiaryContact")
    if contact:
        _send_otp_email(contact, otp, expires_at)
    return


def _handle_mfa_verify(event):
    """
    Handles the API Gateway POST /mfa/verify flow: Verifies OTP and sends secure access link.
    """
    try:
        body = json.loads(event.get('body') or '{}')
        secret_id = body['secretId']
        otp_code = body['otpCode']
    except (json.JSONDecodeError, KeyError):
        return _format_response(400, {"message": "Invalid or missing request body."})
    return _verify_otp(secret_id, otp_code)


def _handle_data_release(event):
    """
    Handles the API Gateway GET /secrets/{secretId}/data flow: Delivers encrypted secret if token is valid.
    """
    path_params = event.get("pathParameters", {})
    query_params = event.get("queryStringParameters", {})
    secret_id = path_params.get("secretId")
    token = query_params.get("token")
    if not (secret_id and token):
        return _format_response(400, {"message": "Missing secretId or token."})
    return _consume_token_and_get_payload(secret_id, token)
