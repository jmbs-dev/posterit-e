import json
import pytest
import time
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from functions.release_lambda import app

@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv('DYNAMODB_TABLE_NAME', 'TestTable')
    monkeypatch.setenv('S3_BUCKET_NAME', 'TestBucket')
    monkeypatch.setenv('SESIdentityArn', 'test@posterite.app')
    monkeypatch.setenv('OTP_TTL_SECONDS', '900')
    monkeypatch.setenv('RELEASE_TOKEN_TTL_SECONDS', '86400')

# --- EventBridge Scheduler (OTP Generation) ---
def test_scheduler_happy_path():
    event = {"source": "aws.scheduler", "secretId": "sec-123"}
    config_item = {"processStatus": "ACTIVATION_PENDING", "beneficiaryMfaContact": "user@example.com"}
    with patch.object(app, 'dynamodb') as mock_dynamodb, \
         patch.object(app, 'ses_client') as mock_ses:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": config_item}
        table.put_item.return_value = {}
        mock_ses.send_email.return_value = {}
        app.lambda_handler(event, None)
        table.put_item.assert_called_once()
        mock_ses.send_email.assert_called_once()
        args, kwargs = mock_ses.send_email.call_args
        assert kwargs['Destination']['ToAddresses'] == [config_item['beneficiaryMfaContact']]
        assert "Verification" in kwargs['Message']['Body']['Text']['Data']

# --- API Gateway POST /mfa/verify ---
def test_mfa_verify_happy_path():
    now = int(time.time())
    event = {
        "httpMethod": "POST",
        "path": "/mfa/verify",
        "body": json.dumps({"secretId": "sec-123", "otp": "654321"})
    }
    otp_item = {
        "PK": "SECRET#sec-123", "SK": "TOKEN#OTP", "otpCode": "654321", "ttl": now + 100
    }
    config_item = {
        "beneficiaryMfaContact": "user@example.com"
    }
    with patch.object(app, 'dynamodb') as mock_dynamodb, \
         patch.object(app, 'ses_client') as mock_ses, \
         patch('uuid.uuid4', return_value=MagicMock(__str__=lambda s: 'token-abc')):
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.side_effect = [ {"Item": otp_item}, {"Item": config_item} ]
        table.put_item.return_value = {}
        table.delete_item.return_value = {}
        mock_ses.send_email.return_value = {}
        response = app.lambda_handler(event, None)
        table.delete_item.assert_called_once_with(
            Key={'PK': 'SECRET#sec-123', 'SK': 'TOKEN#OTP'}
        )
        table.put_item.assert_called_once()
        mock_ses.send_email.assert_called_once()
        assert response['statusCode'] == 200
        assert "secure link" in json.loads(response['body'])['message']

# --- OTP Error Cases ---
def test_mfa_verify_wrong_otp():
    now = int(time.time())
    event = {
        "httpMethod": "POST",
        "path": "/mfa/verify",
        "body": json.dumps({"secretId": "sec-123", "otp": "000000"})
    }
    otp_item = {
        "PK": "SECRET#sec-123", "SK": "TOKEN#OTP", "otpCode": "654321", "ttl": now + 100
    }
    with patch.object(app, 'dynamodb') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": otp_item}
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 401
        assert "Invalid OTP code" in json.loads(response['body'])['message']

def test_mfa_verify_expired_otp():
    now = int(time.time())
    event = {
        "httpMethod": "POST",
        "path": "/mfa/verify",
        "body": json.dumps({"secretId": "sec-123", "otp": "654321"})
    }
    otp_item = {
        "PK": "SECRET#sec-123", "SK": "TOKEN#OTP", "otpCode": "654321", "ttl": now - 100
    }
    with patch.object(app, 'dynamodb') as mock_dynamodb:
        table = MagicMock()
        mock_dynamodb.Table.return_value = table
        table.get_item.return_value = {"Item": otp_item}
        table.delete_item.return_value = {}
        response = app.lambda_handler(event, None)
        assert response['statusCode'] == 401
        assert "OTP expired" in json.loads(response['body'])['message']

# --- API Gateway GET /secrets/{secretId}/data ---
def test_data_release_happy_path():
    event = {
        "httpMethod": "GET",
        "path": "/secrets/sec-123/data",
        "pathParameters": {"secretId": "sec-123"},
        "queryStringParameters": {"token": "token-abc"}
    }
    release_item = {"PK": "SECRET#sec-123", "SK": "TOKEN#RELEASE", "tokenValue": "token-abc", "ttl": int(time.time()) + 100}
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
        table.get_item.side_effect = [ {"Item": release_item}, {"Item": payload_item} ]
        table.delete_item.return_value = {}
        mock_s3.get_object.return_value = {"Body": MagicMock(read=lambda: s3_bytes)}
        response = app.lambda_handler(event, None)
        table.delete_item.assert_called_once_with(
            Key={'PK': 'SECRET#sec-123', 'SK': 'TOKEN#RELEASE'},
            ConditionExpression='tokenValue = :token AND ttl = :ttl',
            ExpressionAttributeValues={':token': 'token-abc', ':ttl': release_item['ttl']}
        )
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
        table.get_item.return_value = {"Item": None}
        table.delete_item.return_value = {}
        response = app.lambda_handler(event, None)
        table.delete_item.assert_not_called()
        mock_s3.get_object.assert_not_called()
        assert response['statusCode'] == 401
        assert "Invalid or expired token" in json.loads(response['body'])['message']
