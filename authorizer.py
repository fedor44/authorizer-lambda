import json
import base64
import boto3
import textwrap
from jose import jwt, JWTError
from botocore.exceptions import ClientError

# kms로 부터 퍼블릭 키 로드    
def get_kms_public_key(kms_client, key_id):
    # KMS에서 공개 키 가져오기
    try:
        response = kms_client.get_public_key(KeyId=key_id)
        public_key = response['PublicKey']
        # base64 인코딩
        public_key_b64 = base64.b64encode(public_key).decode('utf-8')
        
        # PEM 형식으로 변환
        public_key_pem = (
            "-----BEGIN PUBLIC KEY-----\n" +
            '\n'.join(textwrap.wrap(public_key_b64, 64)) +
            "\n-----END PUBLIC KEY-----"
        )
        
        return public_key_pem
    except ClientError as e:
        print(f"Failed to get public key from KMS: {e}")
        policy_context = {
            "message": str(e)
        }
        return generate_policy("nothing", "Deny", "*", policy_context)

# authorizer policy 생성
def generate_policy(principalId, effect, resource, context):
    
    principalId = principalId
        
    policyDocument = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": resource
            }
        ]
    }
    
    # context 예시 (optional -> 클라이언트에게 사용자 정보 전달용)
    context = context

    response = {
        "principalId": principalId,
        "policyDocument": policyDocument,
        "context": context
    }

    print(json.dumps(response))

    return response
    

def lambda_handler(event, context):
    # token 로드
    token = event.get('authorizationToken')
    
    # token 없는 경우 처리
    if not token:
        policy_context = {
            "message": "token not found"
        }
        return generate_policy("nothing", "Deny", "*", policy_context)
    
    try:
        # "Bearer " 접두어 확인
        auth_parts = token.split(" ")
        if auth_parts[0] != "Bearer":
            policy_context = {
                "message": "can not found Bearer string"
            }
            
            return generate_policy("nothing", "Deny", "*", policy_context)
        ## end of handling error
        
        # "Bearer " 접두어 제거
        token = auth_parts[1]
        
        # KMS 클라이언트 생성
        kms_client = boto3.client('kms', region_name='ap-northeast-2')
        
        # 사용할 KMS ARN
        key_id = 'arn:aws:kms:ap-northeast-2:1234567890:key/1234e14b-1234-1234-1234-1234428f0f09'
    
        # KMS에서 공개 키 가져오기
        public_key = get_kms_public_key(kms_client, key_id)            
        
        # claims 로드
        unverified_claims = jwt.get_unverified_claims(token)
        
        # JWT 토큰 검증
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"], audience=unverified_claims['aud'])
        
        print("Token is valid:", decoded_token)
        
        # 사용자 ID 추출
        principalId = decoded_token['sub']  # 일반적으로 'sub' 클레임에 사용자 ID가 포함됨
        
        policy_resource = "arn:aws:execute-api:ap-northeast-2:1234567890:1234d1azo0/test-gateway/*/*"
        policy_context = {
        #    "message": "can not found Bearer string"
        }
        
        return generate_policy(principalId, "Allow", policy_resource, policy_context)

    except JWTError as e:
        policy_context = {
            "message": str(e)
        }
        return generate_policy("nothing", "Deny", "*", policy_context)