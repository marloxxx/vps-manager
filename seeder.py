#!/usr/bin/env python3
"""
User Seeder for VPS Manager
Creates default users for the system
"""

import argparse
import json
from pathlib import Path
from datetime import datetime
from auth import CreateUserRequest, create_user, load_users, save_users, hash_password

# Default users to create
DEFAULT_USERS = [
    {
        "username": "admin",
        "email": "admin@surveyorindonesia.com",
        "password": "admin123",
        "role": "admin"
    },
    {
        "username": "user",
        "email": "user@surveyorindonesia.com", 
        "password": "user123",
        "role": "user"
    },
    {
        "username": "operator",
        "email": "operator@surveyorindonesia.com",
        "password": "operator123", 
        "role": "user"
    },
    {
        "username": "manager",
        "email": "manager@surveyorindonesia.com",
        "password": "manager123",
        "role": "admin"
    }
]

def seed_users(users_data=None, force=False):
    """Seed users into the database"""
    if users_data is None:
        users_data = DEFAULT_USERS
    
    existing_users = load_users()
    
    print("🌱 Starting user seeding...")
    print(f"📊 Found {len(existing_users)} existing users")
    
    created_count = 0
    skipped_count = 0
    
    for user_data in users_data:
        username = user_data["username"]
        
        if username in existing_users and not force:
            print(f"⏭️  User '{username}' already exists, skipping...")
            skipped_count += 1
            continue
        
        try:
            if force and username in existing_users:
                print(f"🔄 Overwriting existing user '{username}'...")
            
            # Create user request
            create_request = CreateUserRequest(**user_data)
            
            # If forcing and user exists, update directly
            if force and username in existing_users:
                existing_users[username].email = user_data["email"]
                existing_users[username].role = user_data["role"]
                existing_users[username].password_hash = hash_password(user_data["password"])
                save_users(existing_users)
                print(f"✅ User '{username}' updated successfully")
            else:
                # Create new user
                new_user = create_user(create_request)
                print(f"✅ User '{username}' created successfully")
            
            created_count += 1
            
        except ValueError as e:
            print(f"❌ Error creating user '{username}': {e}")
            skipped_count += 1
        except Exception as e:
            print(f"❌ Unexpected error creating user '{username}': {e}")
            skipped_count += 1
    
    print(f"\n📈 Seeding completed:")
    print(f"   ✅ Created/Updated: {created_count}")
    print(f"   ⏭️  Skipped: {skipped_count}")
    print(f"   📊 Total users: {len(load_users())}")

def list_users():
    """List all existing users"""
    users = load_users()
    
    if not users:
        print("📭 No users found in the database")
        return
    
    print(f"👥 Found {len(users)} users:")
    print()
    
    for username, user in users.items():
        print(f"👤 {username}")
        print(f"   📧 Email: {user.email}")
        print(f"   🔑 Role: {user.role}")
        print(f"   📅 Created: {user.created_at}")
        print(f"   🕐 Last Login: {user.last_login or 'Never'}")
        print()

def create_custom_user(username, email, password, role="user"):
    """Create a single custom user"""
    try:
        user_data = CreateUserRequest(
            username=username,
            email=email,
            password=password,
            role=role
        )
        
        new_user = create_user(user_data)
        print(f"✅ User '{username}' created successfully")
        print(f"   📧 Email: {email}")
        print(f"   🔑 Role: {role}")
        
    except ValueError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def delete_user(username):
    """Delete a user"""
    users = load_users()
    
    if username not in users:
        print(f"❌ User '{username}' not found")
        return
    
    del users[username]
    save_users(users)
    print(f"🗑️  User '{username}' deleted successfully")

def reset_password(username, new_password):
    """Reset user password"""
    users = load_users()
    
    if username not in users:
        print(f"❌ User '{username}' not found")
        return
    
    users[username].password_hash = hash_password(new_password)
    save_users(users)
    print(f"🔑 Password reset for user '{username}'")

def main():
    parser = argparse.ArgumentParser(description="VPS Manager User Seeder")
    parser.add_argument("action", choices=["seed", "list", "create", "delete", "reset-password"],
                       help="Action to perform")
    parser.add_argument("--force", action="store_true", 
                       help="Force overwrite existing users when seeding")
    parser.add_argument("--username", help="Username for create/delete/reset-password actions")
    parser.add_argument("--email", help="Email for create action")
    parser.add_argument("--password", help="Password for create/reset-password actions")
    parser.add_argument("--role", choices=["admin", "user"], default="user",
                       help="Role for create action")
    
    args = parser.parse_args()
    
    print("🚀 VPS Manager User Seeder")
    print("=" * 40)
    
    if args.action == "seed":
        seed_users(force=args.force)
    
    elif args.action == "list":
        list_users()
    
    elif args.action == "create":
        if not all([args.username, args.email, args.password]):
            print("❌ Error: --username, --email, and --password are required for create action")
            return
        create_custom_user(args.username, args.email, args.password, args.role)
    
    elif args.action == "delete":
        if not args.username:
            print("❌ Error: --username is required for delete action")
            return
        
        confirm = input(f"⚠️  Are you sure you want to delete user '{args.username}'? (y/N): ")
        if confirm.lower() == 'y':
            delete_user(args.username)
        else:
            print("❌ Operation cancelled")
    
    elif args.action == "reset-password":
        if not all([args.username, args.password]):
            print("❌ Error: --username and --password are required for reset-password action")
            return
        reset_password(args.username, args.password)

if __name__ == "__main__":
    main()
