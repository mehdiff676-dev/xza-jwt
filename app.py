import os
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
import my_pb2
import output_pb2
import jwt

app = Flask(__name__)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

@app.route('/access-jwt', methods=['GET'])
def majorlogin_jwt():
    access_token = request.args.get('access_token')
    open_id = request.args.get('open_id')
    platform_type = request.args.get('platform_type')

    if not access_token or not open_id or not platform_type:
        return jsonify({"message": "missing access_token, open_id, platform_type"}), 400

    try:
        platform_type = int(platform_type)
    except ValueError:
        return jsonify({"message": "invalid platform_type"}), 400

    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = platform_type
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)

    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message(serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')
    payload_bytes = bytes.fromhex(hex_encrypted_data)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'Expect': '100-continue',
        'Authorization': f'Bearer {access_token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB51',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
        'Host': 'clientbp.common.ggbluefox.com',
        'Connection': 'close',
        'Accept-Encoding': 'gzip, deflate, br',
    }

    try:
        response = requests.post(url, data=payload_bytes, headers=headers, verify=False, timeout=5)

        if response.status_code == 200:
            try:
                example_msg = output_pb2.Garena_420()
                example_msg.ParseFromString(response.content)
                data_dict = {field.name: getattr(example_msg, field.name)
                            for field in example_msg.DESCRIPTOR.fields
                            if field.name not in ["binary", "binary_data", "Garena420"]}
            except Exception:
                try:
                    data_dict = response.json()
                except ValueError:
                    return jsonify({"message": response.text}), 200

            token_value = data_dict.get("token", None)
            nickname_value = data_dict.get("nickname", "unknown")

            if not token_value:
                return jsonify({"message": "No token found in response"}), 200

            try:
                jwt.decode(token_value, options={"verify_signature": False})
            except Exception:
                pass

            result = {
                "@X_Z_A_Xx": {
                    "token": token_value
                }
            }
            return jsonify(result), 200

        else:
            try:
                return jsonify(response.json()), response.status_code
            except ValueError:
                return jsonify({"message": response.text}), response.status_code

    except requests.RequestException as e:
        return jsonify({"message": str(e)}), 500


@app.route('/get-jwt', methods=['GET'])
def oauth_guest():
    uid = request.args.get('uid')
    password = request.args.get('password')
    if not uid or not password:
        return jsonify({"message": "Missing uid or password"}), 400

    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }

    try:
        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=5)
    except requests.RequestException as e:
        return jsonify({"message": str(e)}), 500

    if oauth_response.status_code != 200:
        try:
            return jsonify(oauth_response.json()), oauth_response.status_code
        except ValueError:
            return jsonify({"message": oauth_response.text}), oauth_response.status_code

    try:
        oauth_data = oauth_response.json()
    except ValueError:
        return jsonify({"message": "Invalid JSON response from OAuth service"}), 500

    if 'access_token' not in oauth_data or 'open_id' not in oauth_data:
        return jsonify({"message": "OAuth response missing access_token or open_id"}), 500

    params = {
        'access_token': oauth_data['access_token'],
        'open_id': oauth_data['open_id'],
        'platform_type': str(oauth_data.get('platform', 4))
    }

    with app.test_request_context('/access-jwt', query_string=params):
        return majorlogin_jwt()


if __name__ == '__main__':
    # Render يعين المنفذ تلقائيًا داخل المتغير PORT
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)