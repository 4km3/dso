import subprocess
import json
from pathlib import Path
import hashlib
import secrets
import sqlite3
from typing import Any, List
import tempfile
import os

def secure_deserialization(user_data: str) -> Any:
    """Use JSON instead of pickle for deserialization"""
    return json.loads(user_data)

def validate_command(command: List[str]) -> bool:
    """
    Validate command and arguments against an allowlist.
    Returns True if command is allowed, False otherwise.
    """
    # Define allowlist of permitted commands and their allowed arguments
    ALLOWED_COMMANDS = {
        'echo': {'max_args': 1, 'allowed_chars': set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-_')},
        'ls': {'max_args': 2, 'allowed_chars': set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/')},
        # Add other allowed commands here
    }
    
    if not command or not isinstance(command, list):
        return False
        
    base_command = command[0]
    if base_command not in ALLOWED_COMMANDS:
        return False
        
    command_rules = ALLOWED_COMMANDS[base_command]
    
    # Check number of arguments
    if len(command) - 1 > command_rules['max_args']:
        return False
        
    # Validate each argument against allowed characters
    for arg in command[1:]:
        if not isinstance(arg, str):
            return False
        if not set(arg).issubset(command_rules['allowed_chars']):
            return False
            
    return True

def secure_command_execution(command: List[str]) -> bytes:
    """
    Execute commands securely with strict validation and execution controls.
    
    Args:
        command: List of command and its arguments
        
    Returns:
        Command output as bytes
        
    Raises:
        SecurityError: If command validation fails
        subprocess.SubprocessError: If command execution fails
    """
    class SecurityError(Exception):
        pass
    
    if not validate_command(command):
        raise SecurityError(f"Command validation failed: {command}")
    
    try:
        # Set up a restricted execution environment
        env = {
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'LANG': 'C.UTF-8',
        }
        
        result = subprocess.run(
            command,
            shell=False,
            check=True,
            capture_output=True,
            env=env,
            timeout=30,  # Set maximum execution time
            cwd='/tmp',  # Set safe working directory
            start_new_session=True  # Isolate process group
        )
        return result.stdout
        
    except subprocess.SubprocessError as e:
        # Log the error securely
        import logging
        logging.error("Command execution failed: %s", str(e))
        raise

def secure_yaml_load(data: str) -> Any:
    """Use safe_load instead of load"""
    import yaml
    return yaml.safe_load(data)

def secure_password_hash(password: str) -> str:
    """Use strong password hashing with Argon2"""
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    return ph.hash(password)

def get_database_password() -> str:
    """Retrieve password from environment variable"""
    password = os.environ.get('DB_PASSWORD')
    if not password:
        raise ValueError("Database password not configured")
    return password

def secure_temp_file() -> None:
    """Create temporary files securely"""
    # Use mkstemp instead of mktemp
    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'w') as f:
            f.write('sensitive data')
        # Process the file...
    finally:
        # Always clean up
        os.unlink(temp_path)

def secure_database_query(user_id: int) -> List[tuple]:
    """Execute SQL queries with parameterization"""
    conn = sqlite3.connect('example.db')
    try:
        cursor = conn.cursor()
        # Use parameterized queries
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchall()
    finally:
        conn.close()

def main() -> None:
    # Example usage of secure functions
    try:
        # Secure JSON deserialization
        user_data = '{"name": "test", "id": 123}'
        secure_deserialization(user_data)
        
        # Secure command execution
        secure_command_execution(['echo', 'safe command'])
        
        # Secure YAML parsing
        secure_yaml_load("key: value")
        
        # Secure password hashing
        secure_password_hash("user_password")
        
        # Secure database access
        db_password = get_database_password()
        
        # Secure temporary file handling
        secure_temp_file()
        
        # Secure database query
        secure_database_query(1)
        
    except Exception as e:
        # Log the error securely
        import logging
        logging.error("Error in main: %s", str(e))
        raise

if __name__ == "__main__":
    main()