def email_check():
    email = input("Enter your email address: ")
    if "@" in email and "." in email:
        print("Valid email address.")
    else:
        print("Invalid email address. Please try again.")
        email_check()  # Recursively call the function until a valid email is entered