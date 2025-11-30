import os
import json
import boto3
import hmac
import uuid
import base64
import time
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# --- Constants ---
CONFIG_SK = "CONFIG"
ENCRYPTED_PAYLOAD_SK = "ENCRYPTED_PAYLOAD"
OTP_SK = "TOKEN#OTP"
RELEASE_SK = "TOKEN#RELEASE"
OTP_TTL_SECONDS = int(os.environ.get('OTP_TTL_SECONDS', 900))  # 15 minutes default
RELEASE_TOKEN_TTL_SECONDS = int(os.environ.get('RELEASE_TOKEN_TTL_SECONDS', 86400))  # 1 day default
BASE_URL = os.environ.get('BASE_URL', 'https://posterite.app')
SENDER_EMAIL_ADDRESS = os.environ.get('SENDER_EMAIL_ADDRESS')
OTP_URL_BASE = BASE_URL + '/otp'

# --- AWS Clients ---
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')
ses_client = boto3.client('ses')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Lambda Handler ---
def lambda_handler(event, context):
    """
    Main Lambda handler for release_lambda.
    Routes the event to the correct flow based on the trigger source and HTTP method.
    Handles MFA initiation, MFA verification, and secure data release.
    """
    request_id = getattr(context, 'aws_request_id', None)
    event_type = event.get("source") or event.get("httpMethod")
    secret_id = event.get("secretId") or (event.get("pathParameters", {}) or {}).get("secretId")
    logger.info(f"ReleaseLambda invoked. RequestId: {request_id}, EventType: {event_type}, SecretId: {secret_id}")
    try:
        if event.get("source") == "aws.scheduler":
            return handle_scheduler_event(event, request_id)
        if event.get("httpMethod") == "POST" and event.get("path") == "/mfa/verify":
            return handle_mfa_verify_event(event, request_id)
        if event.get("httpMethod") == "GET" and event.get("path", "").endswith("/data"):
            return handle_data_release_event(event, request_id)
        logger.warning(f"No matching route found. RequestId: {request_id}, Event: {json.dumps(event)}")
        return format_response(404, {"message": "Not found."})
    except Exception as e:
        logger.error(f"Unhandled exception in lambda_handler. RequestId: {request_id}, Error: {e}", exc_info=True)
        return format_response(500, {"message": "Internal Server Error."})

# --- Event Routing Functions ---
def handle_scheduler_event(event, request_id):
    """
    Handles EventBridge Scheduler trigger for MFA initiation.
    """
    return initiate_mfa_verification(event, request_id)

def handle_mfa_verify_event(event, request_id):
    """
    Handles API Gateway POST /mfa/verify for OTP verification and release token creation.
    """
    return process_mfa_verification(event, request_id)

def handle_data_release_event(event, request_id):
    """
    Handles API Gateway GET /secrets/{secretId}/data for secure data release.
    """
    return process_data_release(event, request_id)

# --- Utility Functions ---
def get_env(var, default=None):
    """Get environment variable with optional default."""
    return os.environ.get(var, default)

def format_response(status_code, body_dict):
    """Format HTTP response for API Gateway with CORS headers."""
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(body_dict),
    }

def get_dynamodb_table():
    """Return DynamoDB table resource."""
    return dynamodb.Table(get_env('DYNAMODB_TABLE_NAME'))

# --- Core Logic Functions ---
def initiate_mfa_verification(event, request_id):
    """
    Generate OTP, store as ephemeral item, and send via email.
    """
    secret_id = event.get("secretId")
    logger.info(f"MFA initiation started. RequestId: {request_id}, SecretId: {secret_id}")
    if not secret_id:
        logger.warning("No secretId provided for MFA initiation.")
        return
    config = get_secret_config(secret_id)
    if not config:
        logger.warning("Secret config not found for secretId: {secret_id}.")
        return
    if config.get("processStatus") != "ACTIVATION_PENDING":
        logger.warning("SecretId: {secret_id} not in ACTIVATION_PENDING state.")
        return
    otp = str(uuid.uuid4().int)[-6:]
    expires_at = int(time.time()) + OTP_TTL_SECONDS
    table = get_dynamodb_table()
    pk = f"SECRET#{secret_id}"
    # Store OTP as ephemeral item
    try:
        table.put_item(
            Item={
                "PK": pk,
                "SK": OTP_SK,
                "otpCode": otp,
                "ttl": expires_at
            }
        )
    except ClientError as e:
        logger.error(f"DynamoDB put_item error for OTP: {e}")
        return
    contact = config.get("beneficiaryMfaContact")
    if contact:
        send_otp_email(contact, otp, expires_at, secret_id)
    logger.info(f"MFA initiation completed for secretId: {secret_id}.")
    return

def process_mfa_verification(event, request_id):
    """
    Verify OTP, delete OTP item, create release token, and send secure link.
    """
    try:
        body = json.loads(event.get('body') or '{}')
        secret_id = body.get('secretId')
        otp_code = body.get('otp')
    except (json.JSONDecodeError, KeyError):
        logger.warning("Invalid or missing request body for MFA verify.")
        return format_response(400, {"message": "Invalid or missing request body."})
    return verify_otp_and_create_release_token(secret_id, otp_code, request_id)

def process_data_release(event, request_id):
    """
    Validate release token, delete it, and return encrypted payload.
    """
    path_params = event.get("pathParameters", {})
    query_params = event.get("queryStringParameters", {})
    secret_id = path_params.get("secretId")
    token = query_params.get("token")
    if not (secret_id and token):
        logger.warning("Missing secretId or token for data release.")
        return format_response(400, {"message": "Missing secretId or token."})
    return consume_release_token_and_get_payload(secret_id, token, request_id)

# --- DynamoDB Access Functions ---
def get_secret_config(secret_id, projection=None):
    """Retrieve CONFIG item for a given secretId."""
    table = get_dynamodb_table()
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

def get_encrypted_payload(secret_id):
    """Retrieve ENCRYPTED_PAYLOAD item for a given secretId."""
    table = get_dynamodb_table()
    pk = f"SECRET#{secret_id}"
    try:
        response = table.get_item(Key={"PK": pk, "SK": ENCRYPTED_PAYLOAD_SK})
    except ClientError as e:
        logger.error(f"DynamoDB get_item error: {e}")
        return None
    return response.get("Item")

# --- Email Functions ---
def send_otp_email(contact, otp, expires_at, secret_id):
    """
    Send OTP code to beneficiary via SES email.
    """
    expires_str = datetime.fromtimestamp(expires_at, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    subject = "Posterit-E: Verificación para liberar tu secreto"
    otp_url = f"{OTP_URL_BASE}?secretId={secret_id}"
    body = (
        f"Para liberar tu secreto, ingresa el siguiente código de verificación en el formulario del siguiente enlace:\n\n"
        f"Código de verificación: {otp}\n\n"
        f"Enlace al formulario: {otp_url}\n\n"
        f"Este código expira el {expires_str}. Si no solicitaste esta acción, por favor ignora este mensaje."
    )
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

def send_release_email(contact, secret_id, token):
    """
    Send secure access link to beneficiary via SES email.
    """
    link = f"{BASE_URL}/secrets/{secret_id}/data?token={token}"
    subject = "Posterit-E: Enlace seguro para acceder a tu secreto"
    body = (
        f"Puedes acceder a tu secreto utilizando el siguiente enlace (válido por 1 día):\n{link}\n\n"
        f"Si no solicitaste esta acción, por favor ignora este mensaje."
    )
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

# --- OTP and Release Token Logic ---
def verify_otp_and_create_release_token(secret_id, otp_code, request_id=None):
    """
    Verify OTP, delete OTP item, create release token, and send secure link.
    """
    table = get_dynamodb_table()
    pk = f"SECRET#{secret_id}"
    # Retrieve OTP item
    try:
        otp_item = table.get_item(Key={"PK": pk, "SK": OTP_SK}).get("Item")
    except ClientError as e:
        logger.error(f"DynamoDB get_item error for OTP: {e}")
        return format_response(500, {"message": "Internal error."})
    now = int(time.time())
    if not otp_item:
        logger.info(f"OTP not found or expired for secretId: {secret_id}.")
        return format_response(401, {"message": "OTP expired or invalid."})
    if now > int(otp_item.get("ttl", 0)):
        logger.info(f"OTP expired for secretId: {secret_id}.")
        table.delete_item(Key={"PK": pk, "SK": OTP_SK})
        return format_response(401, {"message": "OTP expired."})
    stored_otp = otp_item.get("otpCode")
    if not stored_otp or not hmac.compare_digest(str(otp_code), str(stored_otp)):
        logger.info(f"Invalid OTP code for secretId: {secret_id}.")
        return format_response(401, {"message": "Invalid OTP code."})
    # OTP valid: delete OTP item to prevent replay
    table.delete_item(Key={"PK": pk, "SK": OTP_SK})
    # Create release token
    release_token = str(uuid.uuid4())
    release_token_expires = now + RELEASE_TOKEN_TTL_SECONDS
    try:
        table.put_item(
            Item={
                "PK": pk,
                "SK": RELEASE_SK,
                "tokenValue": release_token,
                "ttl": release_token_expires
            }
        )
    except ClientError as e:
        logger.error(f"DynamoDB put_item error for release token: {e}")
        return format_response(500, {"message": "Internal error creating release token."})
    # Send release email
    config = get_secret_config(secret_id)
    contact = config.get("beneficiaryMfaContact") if config else None
    if contact:
        send_release_email(contact, secret_id, release_token)
    logger.info(f"Release process completed for secretId: {secret_id}.")
    return format_response(200, {"message": "Verification successful. You will receive a secure link to access your secret."})

def consume_release_token_and_get_payload(secret_id, token, request_id=None):
    """
    Atomically consume (delete) the release token and return encrypted payload.
    Uses ConditionExpression to prevent race conditions.
    """
    table = get_dynamodb_table()
    pk = f"SECRET#{secret_id}"
    sk = RELEASE_SK
    try:
        response = table.get_item(Key={"PK": pk, "SK": sk})
        release_item = response.get("Item")
        now = int(time.time())
        if not release_item or release_item.get("tokenValue") != token:
            logger.info(f"Invalid or expired release token for secretId: {secret_id}.")
            return format_response(401, {"message": "Invalid or expired token."})
        if now > int(release_item.get("ttl", 0)):
            logger.info(f"Release token expired for secretId: {secret_id}.")
            try:
                table.delete_item(
                    Key={"PK": pk, "SK": sk},
                    ConditionExpression="tokenValue = :token AND #ttl = :ttl",
                    ExpressionAttributeNames={"#ttl": "ttl"},
                    ExpressionAttributeValues={":token": token, ":ttl": int(release_item.get("ttl", 0))}
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'ConditionalCheckFailedException':
                    logger.error(f"DynamoDB atomic delete error: {e}")
            return format_response(401, {"message": "Token expired."})

        try:
            table.delete_item(
                Key={"PK": pk, "SK": sk},
                ConditionExpression="tokenValue = :token AND #ttl = :ttl",
                ExpressionAttributeNames={"#ttl": "ttl"},
                ExpressionAttributeValues={":token": token, ":ttl": int(release_item.get("ttl", 0))}
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.info(f"Release token already consumed for secretId: {secret_id}.")
                return format_response(401, {"message": "Token already consumed or invalid."})
            logger.error(f"DynamoDB atomic delete error: {e}")
            return format_response(500, {"message": "Internal error."})
    except ClientError as e:
        logger.error(f"DynamoDB error for release token for secretId: {secret_id}: {e}")
        return format_response(500, {"message": "Internal error."})
    payload_item = get_encrypted_payload(secret_id)
    if not payload_item:
        logger.warning(f"Encrypted payload not found for secretId: {secret_id}.")
        return format_response(404, {"message": "Encrypted payload not found."})
    encrypted_dek = payload_item.get("encryptedDek")
    salt_kek = payload_item.get("saltKek")
    s3_key = payload_item.get("s3ObjectKey")
    if not (encrypted_dek and salt_kek and s3_key):
        logger.error(f"Incomplete payload metadata for secretId: {secret_id}.")
        return format_response(500, {"message": "Incomplete payload metadata."})
    try:
        s3_obj = s3_client.get_object(Bucket=get_env('S3_BUCKET_NAME'), Key=s3_key)
        encrypted_secret_bytes = s3_obj["Body"].read()
        encrypted_secret_b64 = base64.b64encode(encrypted_secret_bytes).decode()
    except ClientError as e:
        logger.error(f"S3 get_object error for secretId: {secret_id}: {e}")
        return format_response(500, {"message": "Error retrieving encrypted secret."})
    logger.info(f"Payload delivered for secretId: {secret_id}.")
    payload = {
        "encryptedSecret": encrypted_secret_b64,
        "encryptedDek": encrypted_dek,
        "saltKek": salt_kek
    }
    return format_response(200, payload)
