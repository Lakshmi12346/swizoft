# User Authentication System

A production-ready user authentication system built with Django, featuring secure authentication, role-based access control, and auto session timeout.

## Features

### ✅ Core Authentication Features
- **User Registration** with email validation and password strength check
- **Secure Login** with email verification requirement
- **Logout** with session termination
- **Password Reset** via email (token-based)
- **Email Verification** before allowing login

### 🔐 Security Features
- **Password Hashing** using Django's built-in PBKDF2 with SHA256
- **Session Management** with Redis caching
- **CSRF Protection** enabled
- **Secure Cookie Settings**
- **Role-Based Access Control** (Admin/User)

### ⏱️ Auto Session Timeout
- **15-minute inactivity timeout**
- **Browser-based countdown warnings**
- **Automatic logout** with session cleanup
- **Session extension** on user activity

### 🛠️ Technical Stack
- **Backend**: Django 5.0 + Django REST Framework
- **Database**: PostgreSQL
- **Cache**: Redis
- **Authentication**: JWT + Session-based
- **Frontend**: Bootstrap 5 + Django Templates

## Setup Instructions

### Prerequisites
- Python 3.10+
- PostgreSQL
- Redis
- Virtual Environment

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd user_auth_system