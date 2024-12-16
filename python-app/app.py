import subprocess
import pickle
import yaml
import tempfile
import hashlib

def insecure_deserialization(user_data):
    # B301: Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data
    return pickle.loads(user_data)

def command_injection(user_input):
    # B602: subprocess call with shell=True identified
    result = subprocess.Popen(f"echo {user_input}", shell=True, stdout=subprocess.PIPE)
    return result.stdout.read()

def yaml_load(data):
    # B506: Use of unsafe yaml load
    return yaml.load(data)

def weak_cryptography(password):
    # B303: Use of weak hash functions (MD5/SHA1)
    return hashlib.md5(password.encode()).hexdigest()

def hardcoded_password():
    # B105: Hardcoded password string
    password = "super_secret_123"
    return f"Connected with password: {password}"

def insecure_temp_file():
    # B108: Probable insecure usage of temp file/directory
    temp = tempfile.mktemp()
    with open(temp, 'w') as f:
        f.write('sensitive data')

def sql_injection(user_id):
    import sqlite3
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # B608: Possible SQL injection vector
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()

def main():
    # Example usage of vulnerable functions
    user_data = b"malicious_pickle_data"
    insecure_deserialization(user_data)
    
    command_injection("user_input; rm -rf /")
    
    yaml_load("malicious_yaml: !!python/object/apply:os.system ['echo pwned']")
    
    weak_cryptography("password123")
    
    hardcoded_password()
    
    insecure_temp_file()
    
    sql_injection("1; DROP TABLE users;")

if __name__ == "__main__":
    main()