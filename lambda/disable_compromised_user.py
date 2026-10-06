import json
import boto3
import os

iam_client = boto3.client('iam')
sns_client = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))

    # Extract the IAM username from the GuardDuty finding structure.
    # GuardDuty findings nest the access key details under detail.resource.accessKeyDetails
    try:
        detail = event.get('detail', {})
        access_key_details = detail.get('resource', {}).get('accessKeyDetails', {})
        username = access_key_details.get('userName')
        access_key_id = access_key_details.get('accessKeyId')
        finding_type = detail.get('type', 'Unknown finding type')
        severity = detail.get('severity', 'Unknown')
    except Exception as e:
        print(f"Error parsing event: {e}")
        username = None
        access_key_id = None
        finding_type = 'Unknown'
        severity = 'Unknown'

    if not username:
        message = "Lambda triggered but no IAM username found in event. No action taken."
        print(message)
        if SNS_TOPIC_ARN:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="Meridian Security: Lambda triggered, no user identified",
                Message=message
            )
        return {'statusCode': 200, 'body': json.dumps(message)}

    actions_taken = []

    # Deactivate all access keys for the compromised user
    try:
        keys = iam_client.list_access_keys(UserName=username)
        for key in keys['AccessKeyMetadata']:
            iam_client.update_access_key(
                UserName=username,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
            actions_taken.append(f"Deactivated access key {key['AccessKeyId']}")
    except Exception as e:
        actions_taken.append(f"Error deactivating access keys: {e}")

    # Attach a deny-all policy as a backstop, in case the user also has console access
    try:
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        }
        iam_client.put_user_policy(
            UserName=username,
            PolicyName='SecurityIncidentDenyAll',
            PolicyDocument=json.dumps(deny_policy)
        )
        actions_taken.append("Attached DenyAll inline policy")
    except Exception as e:
        actions_taken.append(f"Error attaching deny policy: {e}")

    summary = (
        f"SECURITY ACTION TAKEN\n"
        f"User: {username}\n"
        f"Finding: {finding_type} (Severity: {severity})\n"
        f"Actions: {'; '.join(actions_taken)}"
    )
    print(summary)

    if SNS_TOPIC_ARN:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"Meridian Security: {username} disabled",
            Message=summary
        )

    return {'statusCode': 200, 'body': json.dumps(summary)}
