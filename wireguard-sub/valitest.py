import base64

def validate_wireguard_public_key(value):
    """
    Verify wireguard key.
    """
    print(value)
    try:
        decoded_key = base64.standard_b64decode(value)
    except Exception as e:
        print(e)
        return False
 
    if not len(decoded_key) == 32:
        return False


print( validate_wireguard_public_key("cD6mjjP5EE3Jwu/hDYdgX3PDsNFzbTv5mizkJp5ygBA=") )
