import json
import ssl
import time
import requests
from binascii import unhexlify
from flask import Flask, request, render_template
from nostr.delegation import Delegation
from nostr.event import Event, EventKind
from nostr.key import Bip39PrivateKey, PrivateKey, PublicKey
from nostr.relay_manager import RelayManager

from client import client_bp


app = Flask(__name__)
app.register_blueprint(client_bp, url_prefix="/client")

with open('.app_secret', 'r') as secret_file:
    app.secret_key = secret_file.readline()



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

    # Providing the delegatee PK is optional
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
    """ Fetch the ID and description of all supported event kinds """
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
            # We're signing w/the delegatee's PK. Need to include their delegation tag.
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

        time.sleep(1.5) # allow the connections to open

        print("Publishing!")
        relay_manager.publish_event(event)
        time.sleep(1) # allow the messages to send

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
