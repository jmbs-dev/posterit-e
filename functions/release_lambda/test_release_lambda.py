import json
import pytest
import time
from unittest.mock import patch, MagicMock
from functions.release_lambda import app

@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv('DYNAMODB_TABLE_NAME', 'TestTable')
    monkeypatch.setenv('S3_BUCKET_NAME', 'TestBucket')
    monkeypatch.setenv('SESIdentityArn', 'test@posterite.app')

# --- EventBridge Scheduler (Inicio de MFA) ---
def test_scheduler_happy_path():
    event = {"source": "aws.scheduler", "secretId": "sec-123"}
    config_item = {"processStatus": "ACTIVATION_PENDING", "beneficiaryContact": "user@example.com"}
    with patch.object(app, 'dynamodb') as mock_dynamodb, \
         patch.object(app, 'ses_client') as mock_ses:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": config_item}
        table.update_item.return_value = {}
        mock_ses.send_email.return_value = {}
        app.lambda_handler(event, None)
        table.update_item.assert_called_once()
        mock_ses.send_email.assert_called_once()
        args, kwargs = mock_ses.send_email.call_args
        assert kwargs['Destination']['ToAddresses'] == [config_item['beneficiaryContact']]
        assert "verificación" in kwargs['Message']['Body']['Text']['Data']

def test_scheduler_invalid_state():
    event = {"source": "aws.scheduler", "secretId": "sec-123"}
    config_item = {"processStatus": "INITIAL", "beneficiaryContact": "user@example.com"}
    with patch.object(app, 'dynamodb') as mock_dynamodb, \
         patch.object(app, 'ses_client') as mock_ses:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": config_item}
        app.lambda_handler(event, None)
        table.update_item.assert_not_called()
        mock_ses.send_email.assert_not_called()

# --- API Gateway POST /mfa/verify ---
def test_mfa_verify_happy_path():
    now = int(time.time())
    event = {
        "httpMethod": "POST",
        "path": "/mfa/verify",
        "body": json.dumps({"secretId": "sec-123", "otpCode": "654321"})
    }
    config_item = {
        "processStatus": "MFA_PENDING",
        "otpCode": "654321",
        "otpExpiresAt": now + 100,
        "beneficiaryContact": "user@example.com"
    }
    with patch.object(app, 'dynamodb') as mock_dynamodb, \
         patch.object(app, 'ses_client') as mock_ses, \
         patch('uuid.uuid4', return_value=MagicMock(__str__=lambda s: 'token-abc')):
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": config_item}
        table.put_item.return_value = {}
        table.update_item.return_value = {}
        mock_ses.send_email.return_value = {}
        response = app.lambda_handler(event, None)
        table.put_item.assert_called_once()
        table.update_item.assert_called()
        mock_ses.send_email.assert_called_once()
        assert response['statusCode'] == 200
        assert "enlace seguro" in json.loads(response['body'])['message']

def test_mfa_verify_wrong_otp():
    now = int(time.time())
    event = {
        "httpMethod": "POST",
        "path": "/mfa/verify",
        "body": json.dumps({"secretId": "sec-123", "otpCode": "000000"})
    }
    config_item = {
        "processStatus": "MFA_PENDING",
        "otpCode": "654321",
        "otpExpiresAt": now + 100,
        "beneficiaryContact": "user@example.com"
    }
    with patch.object(app, 'dynamodb') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": config_item}
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 401
        assert "Invalid OTP" in json.loads(response['body'])['message']

def test_mfa_verify_expired_otp():
    now = int(time.time())
    event = {
        "httpMethod": "POST",
        "path": "/mfa/verify",
        "body": json.dumps({"secretId": "sec-123", "otpCode": "654321"})
    }
    config_item = {
        "processStatus": "MFA_PENDING",
        "otpCode": "654321",
        "otpExpiresAt": now - 100,
        "beneficiaryContact": "user@example.com"
    }
    with patch.object(app, 'dynamodb') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": config_item}
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 401
        assert "expired" in json.loads(response['body'])['message']

def test_mfa_verify_invalid_state():
    now = int(time.time())
    event = {
        "httpMethod": "POST",
        "path": "/mfa/verify",
        "body": json.dumps({"secretId": "sec-123", "otpCode": "654321"})
    }
    config_item = {
        "processStatus": "INITIAL",
        "otpCode": "654321",
        "otpExpiresAt": now + 100,
        "beneficiaryContact": "user@example.com"
    }
    with patch.object(app, 'dynamodb') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": config_item}
        response = app.lambda_handler(event, None)
        assert response['statusCode'] in (404, 409)

# --- API Gateway GET /secrets/{secretId}/data ---
def test_data_release_happy_path():
    event = {
        "httpMethod": "GET",
        "path": "/secrets/sec-123/data",
        "pathParameters": {"secretId": "sec-123"},
        "queryStringParameters": {"token": "token-abc"}
    }
    token_item = {"PK": "SECRET#sec-123", "SK": "TOKEN#token-abc", "ttl": int(time.time()) + 100}
    payload_item = {
        "encryptedDek": "dek-xyz",
        "saltKek": "salt-xyz",
        "s3ObjectKey": "obj-key-xyz"
    }
    s3_bytes = b"encrypted-bytes"
    with patch.object(app, 'dynamodb') as mock_dynamodb, \
         patch.object(app, 's3_client') as mock_s3:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.delete_item.return_value = {"Attributes": token_item}
        table.get_item.side_effect = [{"Item": payload_item}]
        mock_s3.get_object.return_value = {"Body": MagicMock(read=lambda: s3_bytes)}
        response = app.lambda_handler(event, None)
        table.delete_item.assert_called_once_with(Key={'PK': 'SECRET#sec-123', 'SK': 'TOKEN#token-abc'}, ReturnValues='ALL_OLD')
        table.get_item.assert_called()
        mock_s3.get_object.assert_called_once_with(Bucket='TestBucket', Key='obj-key-xyz')
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['encryptedDek'] == 'dek-xyz'
        assert body['saltKek'] == 'salt-xyz'
        assert body['encryptedSecret']

def test_data_release_invalid_token():
    event = {
        "httpMethod": "GET",
        "path": "/secrets/sec-123/data",
        "pathParameters": {"secretId": "sec-123"},
        "queryStringParameters": {"token": "token-abc"}
    }
    with patch.object(app, 'dynamodb') as mock_dynamodb, \
         patch.object(app, 's3_client') as mock_s3:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.delete_item.return_value = {}  # No Attributes
        response = app.lambda_handler(event, None)
        table.delete_item.assert_called_once()
        table.get_item.assert_not_called()
        mock_s3.get_object.assert_not_called()
        assert response['statusCode'] == 401
        assert "Invalid or expired token" in json.loads(response['body'])['message']
