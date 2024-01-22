#!/usr/bin/env python3
import base64, os, logging, urllib3, python_freeipa, pyotp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

freeipa_replica = os.getenv("freeipa_replica")
freeipa_admin = os.getenv("freeipa_admin")
freeipa_admin_password = os.getenv("freeipa_admin_password")
freeipa_group_required = os.getenv("freeipa_group_required")
username = os.getenv("username")
password = os.getenv("password")
freeipa_verify_ssl = (os.getenv('freeipa_verify_ssl', 'False') == 'True')

AUTH_SUCCESS = "1"
AUTH_FAILURE = "0"

current_file_name = os.path.basename(__file__)
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
    filename=f"/var/log/ovpn_2fa_auth_script.log",
)
python_freeipa_log = logging.getLogger("python_freeipa")
python_freeipa_log.setLevel(logging.CRITICAL)


def respond_with(value, control_path=os.getenv("auth_control_file")):
    with open(control_path, "w") as myfile:
        myfile.write(value)
    exit(0)


def freeipa_login(username, password):
    try:
        client = python_freeipa.ClientMeta(freeipa_replica, verify_ssl=freeipa_verify_ssl)
        client.login(username, password)
        user_info = client.user_show(a_uid=username)
        freeipa_groups = user_info["result"]["memberof_group"]
        freeipa_nested_groups = user_info["result"]["memberofindirect_group"]
        if freeipa_nested_groups:
            all_groups = freeipa_groups + freeipa_nested_groups
        else:
            all_groups = freeipa_groups
        if freeipa_group_required in all_groups:
            logging.info(f"User {username} memberof group {freeipa_group_required}")
            return True
        else:
            logging.warning(
                f"User {username} not member group {freeipa_group_required}"
            )
            return False
    except Exception as e:
        logging.error(f"User: {username} {e}")
        return False


def freeipa_login_admin():
    try:
        client = python_freeipa.ClientMeta(freeipa_replica, verify_ssl=freeipa_verify_ssl)
        client.login(freeipa_admin, freeipa_admin_password)
        return client
    except Exception as e:
        logging.error(f"Service User: {freeipa_admin} Bind Error: {e}")
        respond_with(AUTH_FAILURE)


def return_user_secret(username):
    try:
        secretkey_ipa = freeipa_login_admin().otptoken_find(o_ipatokenowner=username)["result"][
            0
        ]["ipatokenotpkey"][0]["__base64__"]
        try:
            base32_secret = base64.b64decode(secretkey_ipa).decode("utf-8")
            return base32_secret
        except UnicodeDecodeError:
            base32_secret = base64.b32encode(base64.b64decode(secretkey_ipa)).decode("utf-8")
            return base32_secret
    except IndexError:
        logging.error(f"User: {username} Not found otp secret in freeipa, add otp via self-service")
        respond_with(AUTH_FAILURE)
    except Exception as e:
        logging.error(f"User: {username} Get otp function return error: {e}")
        respond_with(AUTH_FAILURE)

def verify_totp(username, otp_pin):
    try:
        totp_secret = return_user_secret(username)
        return pyotp.TOTP(totp_secret).verify(otp_pin)
    except Exception as e:
        logging.error(f"User: {username} verify_totp function return error: {e}")
        respond_with(AUTH_FAILURE)

try:
    if password.startswith("SCRV1"):
        logging.info(f"User: {username} Started ovpn auth")
        scrv, password, challenge_response = password.split(":", 3)
        password = base64.b64decode(password).decode("utf-8")
        otp_pin = int(base64.b64decode(challenge_response))
        if freeipa_login(username=username, password=password):
            logging.info(f"User: {username} Successfully bind")
            if verify_totp(username=username, otp_pin=otp_pin):
                logging.info(f"User: {username} Successfully verify totp")
                respond_with(AUTH_SUCCESS)
            else:
                logging.error(f"User: {username} Failed verify totp")
                respond_with(AUTH_FAILURE)
        else:
            logging.error(f"User: {username} Failed freeipa bind")
            respond_with(AUTH_FAILURE)
    else:
        logging.error(
        f"User: {username} Challenge responce not found, check configuration on client"
        )
        respond_with(AUTH_FAILURE)
except Exception as e:
    logging.error(f"User: {username} Error: {e}")
    respond_with(AUTH_FAILURE)

respond_with(AUTH_FAILURE)