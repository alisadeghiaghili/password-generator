# -*- coding: utf-8 -*-
"""
Created on Tue Aug 26 12:34:58 2025

@author: sadeghi.a
"""
import random
import string

def generate_password(length=16):
    """Generate a secure random password of specified length."""
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Combine all character sets
    all_chars = lowercase + uppercase + digits + symbols
    
    # Ensure password has at least one character from each set
    password = [
        random.choice(lowercase),
        random.choice(uppercase), 
        random.choice(digits),
        random.choice(symbols)
    ]
    
    # Fill remaining length with random characters
    for _ in range(length - 4):
        password.append(random.choice(all_chars))
    
    # Shuffle the password list to randomize positions
    random.shuffle(password)
    
    return ''.join(password)

def generate_multiple_passwords(count=5):
    """Generate multiple passwords for the user to choose from."""
    print(f"Generated {count} secure 16-character passwords:\n")
    for i in range(count):
        password = generate_password()
        print(f"{i+1}. {password}")
    print()

if __name__ == "__main__":
    print("=== 16-Character Password Generator ===\n")
    
    while True:
        print("Options:")
        print("1. Generate a single password")
        print("2. Generate 5 passwords")
        print("3. Generate custom number of passwords")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            password = generate_password()
            print(f"\nGenerated password: {password}\n")
            
        elif choice == "2":
            generate_multiple_passwords(5)
            
        elif choice == "3":
            try:
                count = int(input("How many passwords do you want? "))
                if count > 0:
                    generate_multiple_passwords(count)
                else:
                    print("Please enter a positive number.\n")
            except ValueError:
                print("Please enter a valid number.\n")
                
        elif choice == "4":
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.\n")