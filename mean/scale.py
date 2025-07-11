# mean/scale.py
import base64
import json

# Global variable to keep track of processed proxies
proxy_counter = 0

def read_lines_maybe_base64(file_path):
    """Read a file that may be plain text or base64-encoded.
    Returns a list of non-empty, stripped lines."""
    with open(file_path, 'rb') as f:
        data = f.read()

    # Attempt to treat the whole file as base64
    try:
        # Removed validate=True so that newlines/spaces won't break it
        decoded_bytes = base64.b64decode(data)
        try:
            decoded_text = decoded_bytes.decode('utf-8')
            # Basic heuristic: proxy configs should contain "://"
            if '://' in decoded_text:
                lines = [line.strip() for line in decoded_text.splitlines() if line.strip()]
                print(f"[DEBUG] {file_path} treated as base64; parsed {len(lines)} lines")
                return lines
        except UnicodeDecodeError:
            pass  # Fall through to plain-text handling
    except Exception:
        pass  # Not valid base64, treat as plain text

    # Fallback: treat as plain UTF-8 text
    plain_text = data.decode('utf-8')
    lines = [line.strip() for line in plain_text.splitlines() if line.strip()]
    print(f"[DEBUG] {file_path} treated as plain text; parsed {len(lines)} lines")
    return lines

def rename_vmess_address(proxy, new_address):
    global proxy_counter
    base64_str = proxy.split('://')[1]
    missing_padding = len(base64_str) % 4
    if missing_padding:
        base64_str += '=' * (4 - missing_padding)
    try:
        decoded_str = base64.b64decode(base64_str).decode('utf-8')
        print("Decoded VMess proxy JSON:", decoded_str)  # Debugging
        proxy_json = json.loads(decoded_str)
        proxy_json['add'] = new_address
        proxy_json['ps'] = new_address  # Set remarks to new address
        proxy_counter += 1
        encoded_str = base64.b64encode(json.dumps(proxy_json).encode('utf-8')).decode('utf-8')
        renamed_proxy = 'vmess://' + encoded_str
        print("Renamed VMess proxy:", renamed_proxy)  # Debugging
        return renamed_proxy
    except Exception as e:
        print("Error processing VMess proxy: ", e)
        return None

def rename_vless_address(proxy, new_address):
    global proxy_counter
    try:
        parts = proxy.split('@')
        userinfo = parts[0]
        hostinfo = parts[1].split('#')[0]
        hostinfo_parts = hostinfo.split(':')
        hostinfo_parts[0] = new_address
        hostinfo = ':'.join(hostinfo_parts)
        remarks = new_address  # Set remarks to new address
        renamed_proxy = userinfo + '@' + hostinfo + '#' + remarks
        proxy_counter += 1
        print("Renamed VLess proxy:", renamed_proxy)  # Debugging
        return renamed_proxy
    except Exception as e:
        print("Error processing VLess proxy: ", e)
        return None

def rename_trojan_address(proxy, new_address):
    global proxy_counter
    try:
        parts = proxy.split('@')
        userinfo = parts[0]
        hostinfo = parts[1].split('#')[0]
        hostinfo_parts = hostinfo.split(':')
        hostinfo_parts[0] = new_address
        hostinfo = ':'.join(hostinfo_parts)
        remarks = new_address  # Set remarks to new address
        renamed_proxy = userinfo + '@' + hostinfo + '#' + remarks
        proxy_counter += 1
        print("Renamed Trojan proxy:", renamed_proxy)  # Debugging
        return renamed_proxy
    except Exception as e:
        print("Error processing Trojan proxy: ", e)
        return None

def process_proxies(input_file, ips_file, output_file):
    # Read all proxy configurations from config.txt (plain text or base64)
    proxies = read_lines_maybe_base64(input_file)

    # Read the list of IP addresses, skipping lines that start with "//"
    with open(ips_file, 'r') as ip_f:
        ips = [line.strip() for line in ip_f.readlines() if not line.strip().startswith("//")]

    # Process each configuration with each IP address
    with open(output_file, 'w') as out_f:
        for proxy in proxies:
            for ip in ips:
                if proxy.startswith('vmess://'):
                    renamed_proxy = rename_vmess_address(proxy, ip)
                elif proxy.startswith('vless://'):
                    renamed_proxy = rename_vless_address(proxy, ip)
                elif proxy.startswith('trojan://'):
                    renamed_proxy = rename_trojan_address(proxy, ip)
                else:
                    renamed_proxy = None  # Unsupported scheme

                if renamed_proxy is not None:
                    out_f.write(renamed_proxy + '\n')

# Example usage
input_file  = 'mean/tour'
ips_file    = 'mean/tone'
output_file = 'mean/hover'

process_proxies(input_file, ips_file, output_file)

# Append extra configurations from extra.txt to the output file
extra_file = 'mean/dol'
try:
    extra_configs = read_lines_maybe_base64(extra_file)
    with open(output_file, 'a') as out_f:
        for config in extra_configs:
            out_f.write(config.rstrip('\n') + '\n')
except Exception as e:
    print("Error appending extra configurations: ", e)
