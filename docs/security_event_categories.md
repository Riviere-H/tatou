# Security Event Categories

## Authentication Events
- `auth_success` - Successful login
- `auth_failure` - Login failure 
- `auth_bruteforce` - Brute force detection 
- `token_revoked` - Token revoked
- `session_hijack_attempt` - Session hijack attempt 

## API Security Events
- `sql_injection_attempt` - SQL injection attempt 
- `path_traversal_attempt` - Path traversal attempt 
- `rate_limit_exceeded` - Rate limit exceeded 
- `input_validation_failed` - Input validation failed 

## File Security Events  
- `file_upload_success` - File upload successfully 
- `file_upload_failed` - File upload failed 
- `malicious_file_detected` - Malicious file detection 
- `watermark_tampering` - Watermark tempering attempt

## System Security Events
- `container_escape_attempt` - Container escape attempt 
- `resource_exhaustion` - Resource exhaustion 
- `config_tampering` - configuration tampering 
- `flag_access` - Flag file access

## RMAP Protocol Events
- `rmap_handshake_success` - RMAP handshake success
- `rmap_handshake_failure` - RMAP handshake failed
- `rmap_identity_spoofing` - RMAP identity spoofing 
- `gpg_key_compromise` - GPG key compromise 
