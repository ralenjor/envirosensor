#!/usr/bin/env python3
"""
User Setup Script

Creates default test accounts with properly hashed passwords.
Run this script once during initial setup.

Usage:
    python utils/setup_users.py

Default accounts created:
    - admin / AdminPass123! (administrator role)
    - user1 / UserPass123! (user role)
"""

import os
import sys

# Add project root to path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
sys.path.insert(0, project_root)

# Load environment variables
from dotenv import load_dotenv
load_dotenv(os.path.join(project_root, '.env'))

# Set a temporary SECRET_KEY if not set (just for user creation)
if not os.environ.get('SECRET_KEY'):
    os.environ['SECRET_KEY'] = 'temporary-key-for-setup'

from config import Config
from utils.data_manager import DataManager


def setup_default_users():
    """Create default test user accounts."""
    dm = DataManager(Config)

    # Default accounts
    accounts = [
        {
            'username': 'admin',
            'password': 'AdminPass123!',
            'role': 'administrator'
        },
        {
            'username': 'user1',
            'password': 'UserPass123!',
            'role': 'user'
        }
    ]

    print("Setting up default user accounts...")
    print("-" * 40)

    for account in accounts:
        if dm.get_user(account['username']):
            print(f"User '{account['username']}' already exists, skipping.")
        else:
            success, error_msg = dm.create_user(
                account['username'],
                account['password'],
                account['role']
            )
            if success:
                print(f"Created user '{account['username']}' with role '{account['role']}'")
            else:
                print(f"Failed to create user '{account['username']}': {error_msg}")

    print("-" * 40)
    print("Setup complete!")
    print("\nTest credentials:")
    print("  Admin: admin / AdminPass123!")
    print("  User:  user1 / UserPass123!")


if __name__ == '__main__':
    setup_default_users()
