from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
import random
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
import jwt
import threading
import math

app = Flask(__name__)

# ============ CONFIG ============
MAX_CONCURRENT = 50
BATCH_SIZE = 100
TOKEN_REFRESH_INTERVAL = 5 * 3600  # 5 ঘন্টা
TOKEN_REFRESH_TIMEOUT = 10  # 10 সেকেন্ড

# JWT API URLs (3 টা আলাদা API)
JWT_APIS = [
    "vips-jwt-shappno.vercel.app",
    "jwt-2-shappno.vercel.app",
    "jwt-3-shappno-tqa2.vercel.app"
]

# ============ CACHE ============
account_cache = {}
liked_cache = defaultdict(set)
token_cache = {}  # {uid: (token, timestamp)}
last_refresh_time = {}  # {server_type: timestamp}
refresh_count = {}  # {server_type: count}
api_status = {}  # {api_url: {"working": True/False, "last_check": timestamp}}
executor = ThreadPoolExecutor(max_workers=30)

# ============ TOKEN FUNCTIONS ============
def is_token_expired(token):
    """Check if JWT token is expired"""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get('exp', 0)
        if exp == 0:
            return False
        return time.time() > (exp - 300)  # 5 minutes buffer
    except:
        return False

def refresh_token_from_api(uid, password, api_url, timeout=TOKEN_REFRESH_TIMEOUT):
    """Generate new token from specific API"""
    try:
        encoded_password = urllib.parse.quote(password)
        url = f"https://{api_url}/token?uid={uid}&password={encoded_password}"
        response = requests.get(url, timeout=timeout, verify=False)
        if response.status_code == 200:
            data = response.json()
            token = data.get('token')
            if token:
                return token
    except Exception as e:
        print(f"Refresh failed for {uid} from {api_url}: {e}")
    return None

def check_api_health(api_url):
    """Check if API is working by testing token generation"""
    try:
        # Test with a known working UID and password
        test_uid = "4737850369"
        test_password = "CREATE_BY_SHAPPNO_GAMING_K3mNA9tb"
        url = f"https://{api_url}/token?uid={test_uid}&password={test_password}"
        response = requests.get(url, timeout=5, verify=False)
        if response.status_code == 200:
            data = response.json()
            if data.get('token'):
                api_status[api_url] = {
                    "working": True,
                    "last_check": time.time()
                }
                return True
    except Exception as e:
        print(f"API health check failed for {api_url}: {e}")
    
    api_status[api_url] = {
        "working": False,
        "last_check": time.time()
    }
    return False

def get_working_apis():
    """Get list of working APIs"""
    working_apis = []
    for api in JWT_APIS:
        # Check cache first
        if api in api_status and api_status[api]["working"]:
            if time.time() - api_status[api]["last_check"] < 60:  # 1 minute cache
                working_apis.append(api)
                continue
        
        # Check if API is working
        if check_api_health(api):
            working_apis.append(api)
    
    return working_apis

def refresh_tokens_batch(accounts, api_url):
    """Refresh tokens for a batch of accounts using a specific API"""
    results = {}
    failed_uids = []
    
    for account in accounts:
        uid = account['uid']
        password = account.get('password')
        
        if not password:
            continue
        
        new_token = refresh_token_from_api(uid, password, api_url)
        if new_token:
            results[uid] = new_token
            token_cache[uid] = (new_token, time.time())
        else:
            failed_uids.append(uid)
    
    return results, failed_uids

def refresh_tokens_for_server(server_type):
    """Refresh tokens for a specific server type using multiple APIs"""
    accounts = load_accounts(server_type)
    
    if not accounts:
        return {
            'refreshed': 0,
            'failed': 0,
            'total': 0,
            'failed_uids': [],
            'api_used': 'none'
        }
    
    # Get working APIs
    working_apis = get_working_apis()
    
    if not working_apis:
        print(f"❌ No working APIs found for {server_type}")
        # Try all APIs anyway
        working_apis = JWT_APIS
        print(f"🔄 Trying all APIs anyway: {working_apis}")
    
    print(f"✅ Working APIs for {server_type}: {working_apis}")
    
    # Split accounts among working APIs
    accounts_with_password = [acc for acc in accounts if acc.get('password')]
    total_accounts = len(accounts_with_password)
    
    if total_accounts == 0:
        return {
            'refreshed': 0,
            'failed': 0,
            'total': len(accounts),
            'failed_uids': [],
            'api_used': 'no_password'
        }
    
    # Split accounts evenly among working APIs
    chunk_size = math.ceil(total_accounts / len(working_apis))
    account_chunks = []
    
    for i in range(0, total_accounts, chunk_size):
        chunk = accounts_with_password[i:i + chunk_size]
        account_chunks.append(chunk)
    
    # Assign chunks to APIs
    api_chunks = {}
    for i, chunk in enumerate(account_chunks):
        api = working_apis[i % len(working_apis)]
        if api not in api_chunks:
            api_chunks[api] = []
        api_chunks[api].extend(chunk)
    
    # Process each API chunk
    all_tokens = {}
    total_failed = []
    
    with ThreadPoolExecutor(max_workers=len(api_chunks)) as executor:
        futures = {}
        for api, chunk in api_chunks.items():
            future = executor.submit(refresh_tokens_batch, chunk, api)
            futures[future] = api
        
        for future in as_completed(futures):
            api = futures[future]
            try:
                tokens, failed = future.result(timeout=30)
                all_tokens.update(tokens)
                total_failed.extend(failed)
                print(f"✅ {api}: {len(tokens)} refreshed, {len(failed)} failed")
            except Exception as e:
                print(f"❌ {api} failed: {e}")
                # Mark API as failed
                if api in api_status:
                    api_status[api]["working"] = False
    
    # Update accounts with new tokens
    for account in accounts:
        if account['uid'] in all_tokens:
            account['token'] = all_tokens[account['uid']]
            account['is_token'] = True
    
    # Save tokens to file
    if all_tokens:
        save_tokens_to_file(all_tokens, server_type)
    
    # Update tracking
    last_refresh_time[server_type] = time.time()
    refresh_count[server_type] = refresh_count.get(server_type, 0) + 1
    
    return {
        'refreshed': len(all_tokens),
        'failed': len(total_failed),
        'total': len(accounts),
        'failed_uids': total_failed[:10],
        'api_used': ', '.join(working_apis),
        'api_details': {
            api: {
                'accounts': len(api_chunks.get(api, [])),
                'success': len([uid for uid in all_tokens if uid in [acc['uid'] for acc in api_chunks.get(api, [])]])
            } for api in working_apis
        }
    }

def get_valid_token(account):
    """Get valid token - auto refresh if expired"""
    uid = account['uid']
    
    # Check token cache first
    if uid in token_cache:
        token, timestamp = token_cache[uid]
        if not is_token_expired(token):
            return token
    
    # If account has token and not expired
    if account.get('is_token', False):
        token = account.get('token')
        if token and not is_token_expired(token):
            token_cache[uid] = (token, time.time())
            return token
    
    # If has password, refresh using any working API
    if account.get('password'):
        working_apis = get_working_apis()
        if not working_apis:
            working_apis = JWT_APIS  # Try all if none working
        
        for api in working_apis:
            new_token = refresh_token_from_api(uid, account['password'], api)
            if new_token:
                token_cache[uid] = (new_token, time.time())
                account['token'] = new_token
                account['is_token'] = True
                return new_token
    
    return None

# ============ LOAD ACCOUNTS ============
def load_accounts(server_type='BD'):
    """Load accounts based on server type"""
    if server_type == 'IND':
        filename = "shappno_ind.txt"
    else:
        filename = "shappno_bd.txt"
    
    cache_key = f"accounts_{server_type}"
    if cache_key in account_cache:
        return account_cache[cache_key]
    
    accounts = []
    
    if not os.path.exists(filename):
        print(f"❌ {filename} not found!")
        return []
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                parts = line.split(':', 1)
                uid = parts[0].strip()
                value = parts[1].strip()
                
                if uid and value:
                    # Check if it's a JWT token
                    if '.' in value and len(value) > 50:
                        accounts.append({
                            "uid": uid,
                            "token": value,
                            "is_token": True
                        })
                    else:
                        accounts.append({
                            "uid": uid,
                            "password": value,
                            "is_token": False
                        })
    
    account_cache[cache_key] = accounts
    print(f"✅ Loaded {len(accounts)} accounts from {filename}")
    return accounts

# ============ SAVE TOKENS TO FILE ============
def save_tokens_to_file(tokens, server_type='BD'):
    """Save tokens back to respective file"""
    if server_type == 'IND':
        filename = "shappno_ind.txt"
    else:
        filename = "shappno_bd.txt"
    
    try:
        # Read existing lines
        lines = []
        with open(filename, 'r') as f:
            lines = f.readlines()
        
        # Update with new tokens
        new_lines = []
        updated_uids = set()
        
        for line in lines:
            line_stripped = line.strip()
            if line_stripped and ':' in line_stripped:
                uid = line_stripped.split(':', 1)[0].strip()
                if uid in tokens:
                    new_lines.append(f"{uid}:{tokens[uid]}\n")
                    updated_uids.add(uid)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        # Add new tokens
        for uid, token in tokens.items():
            if uid not in updated_uids:
                new_lines.append(f"{uid}:{token}\n")
        
        # Write back
        with open(filename, 'w') as f:
            f.writelines(new_lines)
        
        print(f"✅ Updated {filename} with {len(tokens)} tokens")
        return True
    except Exception as e:
        print(f"❌ Error saving: {e}")
        return False

# ============ ENCRYPTION ============
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded_message)).decode('utf-8')

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

def enc(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return encrypt_message(message.SerializeToString())

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except:
        return None

# ============ PLAYER INFO ============
def get_player_info_sync(encrypted_uid, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted_uid)
    headers = {
         'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
         'Authorization': f"Bearer {token}",
         'Content-Type': "application/x-www-form-urlencoded",
         'X-GA': "v1 1",
         'ReleaseVersion': "OB54"
    }

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=8)
        return decode_protobuf(response.content)
    except:
        return None

# ============ SEND LIKE ============
def send_like_sync(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }
        
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=5)
        return response.status
    except:
        return 500

def should_refresh_tokens(server_type):
    """Check if tokens need refresh for server type"""
    if server_type not in last_refresh_time:
        return True
    
    elapsed = time.time() - last_refresh_time[server_type]
    return elapsed >= TOKEN_REFRESH_INTERVAL

def process_account_sync(target_uid, encrypted_uid, account, url):
    account_key = f"{account['uid']}:{target_uid}"
    if account_key in liked_cache[target_uid]:
        return 0, account['uid']
    
    # Get valid token (auto refresh if expired)
    token = get_valid_token(account)
    if not token:
        return 500, account['uid']
    
    status = send_like_sync(encrypted_uid, token, url)
    
    if status == 200:
        liked_cache[target_uid].add(account_key)
        return status, account['uid']
    
    return status, account['uid']

def send_all_likes_sync(target_uid, server_name, url, server_type):
    region = server_name
    protobuf_message = create_protobuf_message(target_uid, region)
    encrypted_uid = encrypt_message(protobuf_message)
    
    # Check and refresh tokens if needed
    if should_refresh_tokens(server_type):
        print(f"🔄 Refreshing tokens for {server_type} server...")
        refresh_result = refresh_tokens_for_server(server_type)
        print(f"✅ {server_type} refresh: {refresh_result}")
    
    accounts = load_accounts(server_type)
    if not accounts:
        return {'success': 0, 'failed': 0, 'total': 0}
    
    # Get fresh accounts
    already_liked = liked_cache.get(target_uid, set())
    fresh_accounts = [acc for acc in accounts if f"{acc['uid']}:{target_uid}" not in already_liked]
    
    if not fresh_accounts:
        return {
            'success': 0,
            'failed': 0,
            'total': len(accounts),
            'already_liked': len(already_liked),
            'fresh_used': 0
        }
    
    random.shuffle(fresh_accounts)
    fresh_accounts = fresh_accounts[:2000]
    
    # Process in parallel
    results = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        futures = []
        for acc in fresh_accounts:
            future = executor.submit(process_account_sync, target_uid, encrypted_uid, acc, url)
            futures.append(future)
        
        for future in futures:
            try:
                result = future.result(timeout=10)
                results.append(result)
            except:
                results.append((500, 'unknown'))
    
    successful = 0
    failed = 0
    
    for status, uid in results:
        if status == 200:
            successful += 1
        elif status != 0:
            failed += 1
    
    return {
        'success': successful,
        'failed': failed,
        'total': len(accounts),
        'already_liked': len(already_liked),
        'fresh_used': len(fresh_accounts)
    }

# ============ ROUTES ============
@app.route('/shappno', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name required"}), 400

    valid_servers = ["IND", "BR", "US", "SAC", "NA", "BD", "RU"]
    if server_name not in valid_servers:
        return jsonify({"error": f"Invalid server. Use: {valid_servers}"}), 400

    # Determine server type for accounts
    server_type = 'IND' if server_name == "IND" else 'BD'
    
    accounts = load_accounts(server_type)
    if not accounts:
        return jsonify({"error": f"No accounts found for {server_type}"}), 500
    
    # Get valid token for checking
    check_token = None
    for account in accounts[:3]:
        check_token = get_valid_token(account)
        if check_token:
            break
    
    if not check_token:
        return jsonify({"error": "No valid token found"}), 500
    
    encrypted_uid = enc(uid)

    try:
        before = get_player_info_sync(encrypted_uid, server_name, check_token)
        if before is None:
            return jsonify({"error": "Invalid UID or server", "status": 0}), 200
        
        before_data = json.loads(MessageToJson(before))
        before_like = int(before_data['AccountInfo'].get('Likes', 0))
    except Exception as e:
        return jsonify({"error": f"Data parsing failed: {str(e)}", "status": 0}), 200
    
    if server_name == "IND":
        like_url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        like_url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        like_url = "https://clientbp.ggpolarbear.com/LikeProfile"

    result = send_all_likes_sync(uid, server_name, like_url, server_type)

    try:
        after = get_player_info_sync(encrypted_uid, server_name, check_token)
        if after is None:
            return jsonify({"error": "Could not verify likes", "status": 0}), 200
        
        after_data = json.loads(MessageToJson(after))
        after_like = int(after_data['AccountInfo']['Likes'])
        player_id = int(after_data['AccountInfo']['UID'])
        player_name = str(after_data['AccountInfo']['PlayerNickname'])
        
        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_id,
            "status": status,
            "accounts_used": result.get('fresh_used', 0),
            "successful_likes": result.get('success', 0),
            "total_accounts": result.get('total', 0),
            "already_liked": result.get('already_liked', 0),
            "server_type": server_type,
            "auto_refresh": "Active"
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": 0}), 500

@app.route('/re', methods=['GET'])
def refresh_all_tokens():
    """Manually refresh all tokens for both server types using multiple APIs"""
    # First, check all APIs
    print("🔄 Checking API health...")
    for api in JWT_APIS:
        check_api_health(api)
    
    results = {}
    
    # Refresh BD tokens
    print("🔄 Refreshing BD tokens...")
    bd_result = refresh_tokens_for_server('BD')
    results['BD'] = bd_result
    
    # Refresh IND tokens
    print("🔄 Refreshing IND tokens...")
    ind_result = refresh_tokens_for_server('IND')
    results['IND'] = ind_result
    
    # Get account counts
    bd_accounts = load_accounts('BD')
    ind_accounts = load_accounts('IND')
    
    # Get API status
    api_status_summary = {}
    for api in JWT_APIS:
        if api in api_status:
            api_status_summary[api] = {
                "working": api_status[api]["working"],
                "last_check": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(api_status[api]["last_check"]))
            }
    
    return jsonify({
        "status": "success",
        "message": "All tokens refreshed successfully",
        "results": results,
        "api_status": api_status_summary,
        "working_apis": get_working_apis(),
        "summary": {
            "BD": {
                "total": len(bd_accounts),
                "refreshed": bd_result['refreshed'],
                "failed": bd_result['failed']
            },
            "IND": {
                "total": len(ind_accounts),
                "refreshed": ind_result['refreshed'],
                "failed": ind_result['failed']
            }
        },
        "last_refresh": {
            "BD": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_refresh_time.get('BD', 0))),
            "IND": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_refresh_time.get('IND', 0)))
        },
        "refresh_count": refresh_count
    })

@app.route('/health', methods=['GET'])
def health():
    bd_accounts = load_accounts('BD')
    ind_accounts = load_accounts('IND')
    
    bd_tokens = sum(1 for acc in bd_accounts if acc.get('is_token', False))
    ind_tokens = sum(1 for acc in ind_accounts if acc.get('is_token', False))
    
    next_refresh_bd = 0
    next_refresh_ind = 0
    
    if 'BD' in last_refresh_time:
        next_refresh_bd = max(0, TOKEN_REFRESH_INTERVAL - (time.time() - last_refresh_time['BD']))
    if 'IND' in last_refresh_time:
        next_refresh_ind = max(0, TOKEN_REFRESH_INTERVAL - (time.time() - last_refresh_time['IND']))
    
    # Check API status
    api_status_summary = {}
    for api in JWT_APIS:
        if api in api_status:
            api_status_summary[api] = {
                "working": api_status[api]["working"],
                "last_check": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(api_status[api]["last_check"]))
            }
    
    return jsonify({
        "status": "healthy",
        "accounts": {
            "BD": {
                "total": len(bd_accounts),
                "tokens_available": bd_tokens
            },
            "IND": {
                "total": len(ind_accounts),
                "tokens_available": ind_tokens
            }
        },
        "token_cache": len(token_cache),
        "api_status": api_status_summary,
        "working_apis": get_working_apis(),
        "auto_refresh": {
            "status": "Active",
            "interval": f"{TOKEN_REFRESH_INTERVAL//3600} hours",
            "timeout_per_token": f"{TOKEN_REFRESH_TIMEOUT} seconds",
            "next_refresh": {
                "BD": f"{int(next_refresh_bd//3600)}h {int((next_refresh_bd%3600)//60)}m remaining",
                "IND": f"{int(next_refresh_ind//3600)}h {int((next_refresh_ind%3600)//60)}m remaining"
            }
        }
    })

@app.route('/', methods=['GET'])
def home():
    bd_accounts = load_accounts('BD')
    ind_accounts = load_accounts('IND')
    
    working_apis = get_working_apis()
    
    return jsonify({
        "name": "SHAPPNO API",
        "version": "4.0",
        "features": [
            "Separate accounts for BD and IND servers",
            "Auto token refresh every 5 hours",
            "Manual refresh via /re endpoint",
            "3 JWT APIs with automatic failover",
            "10 second timeout per token refresh",
            "No API key required"
        ],
        "endpoints": {
            "/shappno": "Send likes (uid & server_name required)",
            "/re": "Manually refresh all tokens with load balancing",
            "/health": "Check API status"
        },
        "accounts": {
            "BD": len(bd_accounts),
            "IND": len(ind_accounts)
        },
        "jwt_apis": {
            "total": len(JWT_APIS),
            "working": working_apis
        },
        "credit": "@SHAPPNO"
    })

if __name__ == '__main__':
    print("🚀 SHAPPNO API Started!")
    print("✅ No API key required")
    print("✅ Auto refresh: Every 5 hours")
    print("✅ JWT APIs:", JWT_APIS)
    print("✅ Timeout per token:", TOKEN_REFRESH_TIMEOUT, "seconds")
    print("📁 Reading from: shappno_bd.txt and shappno_ind.txt")
    print("🔧 Manual refresh: /re endpoint")
    app.run(host='0.0.0.0', port=5001, debug=False)