import json
import ssl
import time
import requests
from binascii import unhexlify
from flask import Flask, request, render_template, session
from nostr.delegation import Delegation
from nostr.event import Event, EventKind
from nostr.key import Bip39PrivateKey, PrivateKey, PublicKey
from nostr.relay_manager import RelayManager
from nostr.filter import Filter
import json

import uuid
from datetime import datetime, timedelta

from client import client_bp

app = Flask(__name__)
app.register_blueprint(client_bp, url_prefix="/client")

with open('.app_secret', 'r') as secret_file:
    app.secret_key = secret_file.readline()

# NIP-47 Constants
NWC_REQUEST_KIND = 23194
NWC_RESPONSE_KIND = 23195
NWC_INFO_KIND = 13194

def _send_nwc_request(method_name, params_dict):
    """Helper function to send NWC requests and handle responses."""
    if not all(key in session for key in ['nwc_wallet_pubkey', 'nwc_client_secret', 'nwc_relay_url']):
        return {"status": "error", "message": "No active NWC connection"}

    try:
        # Initialize client's NWC key
        client_privkey = PrivateKey(unhexlify(session['nwc_client_secret']))
        client_pubkey_hex = client_privkey.public_key.hex()

        # Construct request payload
        payload = {
            "method": method_name,
            "params": params_dict
        }
        payload_json = json.dumps(payload)

        # Encrypt payload using NIP-04
        encrypted_content = client_privkey.encrypt_message(
            payload_json,
            session['nwc_wallet_pubkey']
        )

        # Create request event
        request_event = Event(
            kind=NWC_REQUEST_KIND,
            content=encrypted_content,
            tags=[
                ["p", session['nwc_wallet_pubkey']],
                ["expiration", str(int((datetime.now() + timedelta(seconds=60)).timestamp()))]
            ]
        )
        client_privkey.sign_event(request_event)

        # Initialize relay manager and connect
        relay_manager = RelayManager()
        relay_manager.add_relay(session['nwc_relay_url'])
        time.sleep(1.5)  # Wait for connection

        # Publish request event
        relay_manager.publish_event(request_event)
        
        start_time = time.time()
        timeout = 15
        print(f"[{datetime.now()}] Waiting for NWC response (timeout: {timeout}s)...") # Log start
        while time.time() - start_time < timeout:
            time.sleep(0.5)
            
            # Check for new messages in the message pool directly
            while not relay_manager.message_pool.events.empty():
                event = relay_manager.message_pool.events.get()
                # --- Start Debug Logging ---
                print(f"[{datetime.now()}] Received event:")
                print(f"  Kind: {event.kind}")
                print(f"  Pubkey: {event.pubkey}")
                print(f"  Tags: {event.tags}")
                print(f"  Content Length: {len(event.content)}")
                # --- End Debug Logging ---

                # Check if this is a response to our request
                if (event.kind == NWC_RESPONSE_KIND and 
                    event.pubkey == session['nwc_wallet_pubkey'] and
                    any(tag[0] == "e" and tag[1] == request_event.id for tag in event.tags)):
                    
                    print(f"[{datetime.now()}] Matched response event!") # Log match
                    # Decrypt response
                    decrypted_content = client_privkey.decrypt_message(
                        event.content,
                        session['nwc_wallet_pubkey']
                    )
                    response_data = json.loads(decrypted_content)
                    
                    # Clean up
                    relay_manager.close_all_relay_connections()
                    
                    if "error" in response_data:
                        return {
                            "status": "error",
                            "message": response_data["error"].get("message", "Unknown error")
                        }
                    return {
                        "status": "success",
                        "data": response_data.get("result", {})
                    }

        # Timeout
        print(f"[{datetime.now()}] Timeout reached waiting for response.") # Log timeout
        relay_manager.close_all_relay_connections()
        return {"status": "error", "message": "Timeout waiting for wallet response"}

    except Exception as e:
        return {"status": "error", "message": str(e)}
    


NWC_INFO_KIND = 13194


@app.route("/nwc/connect_and_fetch_info", methods=['POST'])
def nwc_connect_and_fetch_info():
    try:
        nwc_uri = request.form['nwc_uri']
        print(f"NWC URI: {nwc_uri}")
        if not nwc_uri.startswith('nostr+walletconnect://'):
            return {"status": "error", "message": "Invalid NWC URI format"}

        uri_parts = nwc_uri.replace('nostr+walletconnect://', '').split('?')
        if len(uri_parts) != 2 or not uri_parts[0]: # Ensure pubkey part exists
             return {"status": "error", "message": "Invalid NWC URI format (missing pubkey or ?)"}
        
        wallet_pubkey = uri_parts[0]
        query_string = uri_parts[1]

        params = {}
        for param in query_string.split('&'): # Parse the query string part
            key_value = param.split('=')
            if len(key_value) == 2:
                params[key_value[0]] = key_value[1]

        print(f"Parsed NWC params: {params}")
        if 'relay' not in params or 'secret' not in params:
            return {"status": "error", "message": "Missing required NWC parameters (relay, secret)"}
        
        # Store the correctly parsed pubkey
        session['nwc_wallet_pubkey'] = wallet_pubkey 
        session['nwc_client_secret'] = params['secret']
        # Ensure relay URL starts with wss:// for the helper function
        relay_url = params['relay']
        if not relay_url.startswith('wss://'):
             relay_url = f"wss://{relay_url}"
        session['nwc_relay_url'] = relay_url # Store the full URL
        if 'lud16' in params:
            session['nwc_lud16'] = params['lud16']
        print(f"Session: {session}")

        # Send get_info request using the helper function
        result = _send_nwc_request("get_info", {})

        if result["status"] == "success":
            info = result["data"]
            print(f"Parsed wallet info: {info}")
            # Extract relevant info if needed, NIP-47 get_info doesn't define alias or notifications
            # but some wallets might include extra fields. Adapt as necessary.
            return {
                "status": "success",
                "alias": info.get("alias", "N/A"),  # Alias isn't standard in get_info response
                "methods": info.get("methods", []), # Standard get_info field
                # Wallet Pubkey might be missing in URI, get it from session if populated by helper
                "wallet_pubkey": session.get('nwc_wallet_pubkey', '') 
                # "notifications": info.get("notifications", []) # Not standard, but check anyway
            }
        else:
            print(f"Error fetching wallet info: {result['message']}")
            # Clear session on error? Maybe not, user might want to retry.
            return result # Return the error status and message

    except Exception as e:
        print(f"Error in nwc_connect_and_fetch_info: {str(e)}")
        # Clear session on major error
        session.pop('nwc_wallet_pubkey', None)
        session.pop('nwc_client_secret', None)
        session.pop('nwc_relay_url', None)
        session.pop('nwc_lud16', None)
        return {"status": "error", "message": str(e)}

@app.route("/nwc/get_balance", methods=['POST'])
def nwc_get_balance():
    """Get wallet balance."""
    result = _send_nwc_request("get_balance", {})
    if result["status"] == "success":
        return {
            "status": "success",
            "balance": result["data"].get("balance", 0)
        }
    return result

@app.route("/nwc/pay_invoice", methods=['POST'])
def nwc_pay_invoice():
    """Pay a BOLT11 invoice."""
    invoice = request.form['invoice']
    amount = request.form.get('amount')  # Optional

    params = {"invoice": invoice}
    if amount:
        params["amount"] = int(amount)

    result = _send_nwc_request("pay_invoice", params)
    if result["status"] == "success":
        return {
            "status": "success",
            "preimage": result["data"].get("preimage")
        }
    return result

@app.route("/")
def index():
    print(request.host)
    return render_template("index.html")

@app.route("/key/create", methods=['POST'])
def create_pk():
    mnemonic = None
    type = request.form["type"]
    if type == "raw":
        pk = PrivateKey()
    else:
        pk = Bip39PrivateKey.with_mnemonic_length(int(request.form["mnemonic_length"]))
        mnemonic = ", ".join(pk.mnemonic)

    return dict(
        pk_hex=pk.hex(),
        pk_nsec=pk.bech32(),
        pubkey_hex=pk.public_key.hex(),
        pubkey_npub=pk.public_key.bech32(),
        mnemonic=mnemonic
    )

@app.route("/key/load", methods=['POST'])
def load_pk():
    data_type = request.form["type"]
    privkey_data = request.form["privkey_data"]
    if data_type == "existing":
        if privkey_data.startswith("nsec"):
            pk = PrivateKey.from_nsec(privkey_data)
        else:
            pk = PrivateKey(unhexlify(privkey_data))
    else:
        if "," in privkey_data:
            mnemonic = privkey_data.split(",")
        else:
            mnemonic = privkey_data.split()
        pk = Bip39PrivateKey(mnemonic=mnemonic)

    return dict(
        pk_hex=pk.hex(),
        pk_nsec=pk.bech32(),
        pubkey_hex=pk.public_key.hex(),
        pubkey_npub=pk.public_key.bech32(),
    )

@app.route("/nip26/create", methods=['POST'])
def nip26_create_and_sign_delegation_token():
    delegator_pk = PrivateKey(unhexlify(request.form["delegator_pk_hex"]))
    kinds_list = request.form.get("kinds")
    kinds = [int(k) for k in request.form["kinds"].split(",")] if kinds_list else []
    valid_from = request.form["valid_from"]
    valid_until = request.form["valid_until"]

    delegatee_pk_input = request.form["delegatee_pk"]
    if delegatee_pk_input:
        if delegatee_pk_input.startswith("nsec"):
            delegatee_pk = PrivateKey.from_nsec(delegatee_pk_input)
        else:
            delegatee_pk = PrivateKey(unhexlify(delegatee_pk_input))
    else:
        delegatee_pk = PrivateKey()

    delegation = Delegation(
        delegator_pubkey=delegator_pk.public_key.hex(),
        delegatee_pubkey=delegatee_pk.public_key.hex(),
        event_kinds=kinds,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    delegator_pk.sign_delegation(delegation)

    if delegation.event_kinds:
        kinds_descriptions = [f"{k}: {EventKind.ALL_KINDS[k]}" for k in delegation.event_kinds]
    else:
        kinds_descriptions = ["(ALL)"]

    return dict(
        delegation_token=delegation.delegation_token,
        delegator_npub=delegator_pk.public_key.bech32(),
        delegator_hex=delegator_pk.public_key.hex(),
        delegatee_npub=delegatee_pk.public_key.bech32(),
        delegatee_pubkey_hex=delegatee_pk.public_key.hex(),
        delegatee_nsec=delegatee_pk.bech32(),
        delegatee_privkey_hex=delegatee_pk.hex(),
        event_kinds="\n".join(kinds_descriptions),
        valid_from=delegation.valid_from,
        valid_until=delegation.valid_until,
        signature=delegation.signature,
        delegation_tag=str(delegation.get_tag()),
    )

@app.route("/nip26/sign", methods=['POST'])
def nip26_sign_delegation_token():
    delegator_pk = PrivateKey(unhexlify(request.form["delegator_pk_hex"]))
    delegation_token = request.form["delegation_token"]

    delegatee_pk = None
    delegatee_pk_input = request.form.get("delegatee_pk")
    if delegatee_pk_input:
        if delegatee_pk_input.startswith("nsec"):
            delegatee_pk = PrivateKey.from_nsec(delegatee_pk_input)
        else:
            delegatee_pk = PrivateKey(unhexlify(delegatee_pk_input))

    try:
        delegation = Delegation.from_token(delegator_pubkey=delegator_pk.public_key.hex(), delegation_token=delegation_token)
        delegatee_pubkey = PublicKey(unhexlify(delegation.delegatee_pubkey))
    except Exception as e:
        print(e)

    delegator_pk.sign_delegation(delegation)

    if delegation.event_kinds:
        kinds_descriptions = [f"{k}: {EventKind.ALL_KINDS[k]}" for k in delegation.event_kinds]
    else:
        kinds_descriptions = "(ALL)"

    return dict(
        delegator_npub=delegator_pk.public_key.bech32(),
        delegator_hex=delegator_pk.public_key.hex(),
        delegatee_npub=delegatee_pubkey.bech32(),
        delegatee_pubkey_hex=delegatee_pubkey.hex(),
        delegatee_nsec=delegatee_pk.bech32() if delegatee_pk else None,
        delegatee_privkey_hex=delegatee_pk.hex() if delegatee_pk else None,
        event_kinds="\n".join(kinds_descriptions),
        valid_from=delegation.valid_from,
        valid_until=delegation.valid_until,
        signature=delegation.signature,
        delegation_tag=str(delegation.get_tag()),
    )

@app.route("/event/kinds", methods=['GET'])
def get_event_kinds():
    return dict(kinds=[[k, v] for k, v in EventKind.ALL_KINDS.items()])

@app.route("/event/sign", methods=['POST'])
def event_sign():
    event = None
    pk = PrivateKey(unhexlify(request.form["pk_hex"]))
    data_type = request.form["type"]

    if data_type == "raw_json":
        event_json = request.form["event_data"]
        try:
            event = Event.from_json(event_json)
        except Exception as e:
            print(e)

    else:
        msg = request.form.get("event_data")
        tags = []

        if "metadata" in data_type:
            event_kind = EventKind.SET_METADATA
        elif "contacts" in data_type:
            event_kind = EventKind.CONTACTS
        else:
            event_kind = EventKind.TEXT_NOTE

        if "nip26" in data_type:
            import ast
            delegation_tag = ast.literal_eval(request.form["delegation_tag"])
            tags=[delegation_tag]
        
        event = Event(content=msg, kind=event_kind, tags=tags)

    pk.sign_event(event)

    return dict(
        signature=event.signature,
        event_json=json.dumps(event.to_json(), indent=2),
        note_id=event.note_id,
    )

@app.route("/event/publish", methods=['POST'])
def event_publish():
    event_json = request.form["event_json"]
    relays = request.form["relays"].split()

    try:
        event = Event.from_json(event_json)

        relay_manager = RelayManager()
        for relay in relays:
            relay_manager.add_relay(
                url=f"wss://{relay}",
            )
            print(f"added {relay}")

        time.sleep(1.5)

        print("Publishing!")
        relay_manager.publish_event(event)
        time.sleep(1)

        relay_manager.close_all_relay_connections()
        print("done")
    except Exception as e:
        import traceback
        traceback.print_exc()

    return dict(
        kind=event.kind,
        note_id=event.note_id
    )

@app.route("/nip05/validate", methods=['POST'])
def nip05_validate():
    """
    Validate a NIP-05 identifier against a public key.
    Returns status and optional relays if available.
    """
    identifier = request.form["identifier"]
    pubkey_hex = request.form["pubkey_hex"]

    # Validate identifier format
    if "@" not in identifier or len(identifier.split("@")) != 2:
        return dict(
            status="error",
            message="Invalid identifier format. Expected: <local-part>@<domain>"
        )

    local_part, domain = identifier.split("@")

    # Handle special case: "_@domain" maps to just "domain"
    if local_part == "_":
        local_part = ""

    # Validate local-part characters (a-z0-9-_.)
    import re
    if local_part and not re.match(r'^[a-z0-9\-_\.]+$', local_part, re.IGNORECASE):
        return dict(
            status="error",
            message="Invalid local-part. Allowed characters: a-z0-9-_. (case-insensitive)"
        )

    # Construct the well-known URL
    url = f"https://{domain}/.well-known/nostr.json?name={local_part}"

    try:
        # Make HTTP request without following redirects
        response = requests.get(url, allow_redirects=False, timeout=5)

        # Check for redirects (not allowed per NIP-05)
        if response.status_code in (301, 302, 303, 307, 308):
            return dict(
                status="error",
                message="HTTP redirects are not allowed for NIP-05 endpoints"
            )

        # Check for successful response
        if response.status_code != 200:
            return dict(
                status="error",
                message=f"Failed to fetch NIP-05 data: HTTP {response.status_code}"
            )

        # Parse JSON response
        data = response.json()

        # Check if 'names' key exists
        if "names" not in data or not isinstance(data["names"], dict):
            return dict(
                status="error",
                message="Invalid response: 'names' key missing or not an object"
            )

        # Get the public key for the local-part
        returned_pubkey = data["names"].get(local_part, None)

        if not returned_pubkey:
            return dict(
                status="error",
                message=f"No public key found for {local_part} in response"
            )

        # Validate the returned public key
        if returned_pubkey != pubkey_hex:
            return dict(
                status="error",
                message="Public key mismatch"
            )

        # Check for optional relays
        relays = []
        if "relays" in data and isinstance(data["relays"], dict):
            relays = data["relays"].get(pubkey_hex, [])

        return dict(
            status="success",
            message=f"NIP-05 identifier {identifier} is valid",
            relays=relays
        )

    except requests.exceptions.RequestException as e:
        return dict(
            status="error",
            message=f"Network error: {str(e)}"
        )
    except ValueError:
        return dict(
            status="error",
            message="Invalid JSON response from server"
        )