import json
import os
import requests

def _get_cookie(cookiefile: str) -> (str, str):
    '''Obtain the cookie user/pass for cookie authentication (default)'''
    if not os.path.exists(cookiefile):
        raise FileNotFoundError(
            f"Cookie not found at {cookiefile}. Ensure bitcoind is running and datadir is correct.")
    with open(cookiefile, 'r', encoding='utf-8') as f:
        cookie = f.read().strip()
        if ':' not in cookie:
            raise ValueError(f"Invalid cookiefile format user:hashpass in {cookiefile}.")
    cookie_user, cookie_pass = cookie.split(':', 1)

    return (cookie_user, cookie_pass)

def make_rpc_call(method: str = "getblockchaininfo",
                  params: list = None,
                  user: str = None,
                  password: str = None,
                  datadir: str ="~/.bitcoin",
                  rpc_ip: str = "127.0.0.1",
                  rpc_port: int = 8332) -> int | dict
    '''Handle rpc calls to the bitcoind'''

    headers = {'content-type': 'application/json'}
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or []
    }

    # get auth credentials
    match (user, password):
        case (None, None):  # default to cookie authentication
            datadir = os.path.expanduser(datadir)
            cookie_file = os.path.join(datadir, '.cookie')
            auth = _get_cookie(cookie_file)
        case (None, _):  # error case: no user given
            raise ValueError("rpcuser is required w/ rpcpassword")
        case (_, None):  # error case: no password given
            raise ValueError("rpcpassword is required w/ rpcuser")
        case (_, _): # roll with what the user gave us...
            auth = (user, password)

    # make the request
    try:
        response = requests.post(
            f"http://{rpc_ip}:{rpc_port}",
            auth=auth,
            data=json.dumps(payload),
            headers=headers,
            timeout = 1.5
        )
        response.raise_for_status()  # error on bad HTTP status

        return response.json().get('result')
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

        return None

# these currently assume you are using cookie auth

def getrawtransaction(txid: str,
                      verbosity: int=None,
                      blockhash=None,
                      datadir="~/.bitcoin"):
    '''get transaction from the bitcoind'''
    params = [txid]
    if isinstance(verbosity, int):
        params.append(verbosity)
    if isinstance(blockhash, str):
        params.append(blockhash)

    return make_rpc_call(method='getrawtransaction', params=params, datadir=datadir)
