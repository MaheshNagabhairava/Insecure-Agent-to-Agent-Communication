# Shopping Application

A full-fledged shopping web application built with Flask, featuring user authentication, product catalog, order management, and intentionally placed security vulnerabilities for testing purposes.

## Features

### Core Functionality
- **User Authentication**: Login and registration system with $30,000 starting balance
- **Product Catalog**: 5 sample products with detailed views
- **Shopping Cart**: Add items to cart, manage quantities, review before checkout
- **Wallet System**: Virtual wallet with $30,000 starting balance for all users
- **Order Management**: Place orders from cart and view order history
- **User Profiles**: View and edit profile information
- **Product Reviews**: Read and write product reviews (with XSS vulnerability)
- **Search Functionality**: Search for products and information


### Security Features
- **Anti-CSRF Protection**: CSRF tokens on login and registration forms
- **Rate Limiting**: Applied to login and registration endpoints
- **Password Hashing**: Secure password storage using Werkzeug
- **Session Management**: Secure session handling

### Intentionally Placed Vulnerabilities (For Testing Only)
⚠️ **WARNING**: These vulnerabilities are intentionally placed for security testing purposes:

1. **Blind SQL Injection**: Located in the order placement functionality (`/place_order`) - truly blind with no error messages
2. **Reflected XSS**: Located in the product review system (`/submit_review` and `/product/<id>/reviews`)


## Installation

1. Install Python 3.7 or higher
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

1. Start the Flask application:
   ```bash
   python app.py
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

1. **Register**: Create a new account
2. **Login**: Access your account
3. **Browse Products**: View the product catalog
4. **View Product Details**: Click on any product for more information
5. **Add to Cart**: Add products to your shopping cart
6. **Manage Cart**: Review items, update quantities, remove items
7. **Place Orders**: Place orders from cart using wallet balance (login required)
8. **View Orders**: Check your order history
9. **User Profile**: View and edit your profile information
10. **Product Reviews**: Read and write reviews for products
11. **Search**: Use the search functionality (login required)


## Database

The application uses SQLite database (`shopping.db`) which is automatically created on first run with:
- Users table for authentication
- Products table with 5 sample products
- Orders table for order management

## Security Testing

This application includes intentionally placed vulnerabilities for security testing:

### Blind SQL Injection
- **Location**: Order placement endpoint
- **Test**: Try injecting SQL commands in the product ID parameter
- **Example**: Use payloads like `' AND SLEEP(5)-- -`




### CSRF

## Important Notes

- This application is designed for educational and testing purposes
- The vulnerabilities are intentionally placed and should not be used in production
- Always follow responsible disclosure practices when testing security vulnerabilities
- The application includes proper security measures (CSRF, rate limiting) for non-vulnerable endpoints

## Sample Products

The application comes with 5 sample products:
1. iPhone 15 Pro - $999.99
2. MacBook Air M2 - $1,199.99
3. AirPods Pro - $249.99
4. Apple Watch Series 9 - $399.99
5. iPad Pro - $799.99
