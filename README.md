# Blog Web Application

![Homepage](./public/homepage.png 'Homepage')

## Project Overview

This is a simple blog web application built using **Node.js, Express.js, EJS, and SQLite**. It allows users to create, edit, and delete blog posts while ensuring secure authentication and input sanitization.

## Features

- **User Authentication** (Login & Registration)
- **Create, Edit, and Delete Blog Posts**
- **Secure Password Handling with Bcrypt**
- **Session & Token-Based Authentication with JWT**
- **Rate Limiting for Security**
- **Sanitized User Input to Prevent XSS & SQL Injection**

## Tech Stack

- **Backend**: Node.js, Express.js
- **Frontend**: EJS, CSS
- **Database**: SQLite (Better-SQLite3)
- **Security**: Bcrypt, JSON Web Tokens, Express Rate Limit, Sanitize-HTML

## Installation

### Prerequisites

Ensure you have **Node.js** installed on your machine.

### Steps to Setup

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/amit-kumar-18/blog-app.git
   cd blog_app
   ```
2. **Install Dependencies**:
   ```sh
   npm install
   ```
3. **Set Up Environment Variables**:
   Create a `.env` file in the root directory and add the following:
   ```env
   JWT_KEY=your_secret_key
   ```
4. **Run the Application**:
   ```sh
   npm run dev
   ```
   The application will be running at `http://localhost:3000`

## Project Structure

```
blog_webapp/
│-- middlewares/        # Middleware functions
│-- model/              # Database models
│-- node_modules/       # Dependencies
│-- public/             # Static assets (CSS, JS, images)
│-- routes/             # Express routes
│-- views/              # EJS templates
│-- .env                # Environment variables
│-- .gitignore          # Ignored files
│-- blogApp.db          # SQLite database
│-- package.json        # Project metadata & dependencies
│-- package-lock.json   # Lockfile
│-- server.js           # Main server file
```

## API Endpoints

| Method | Endpoint       | Description            |
| ------ | -------------- | ---------------------- |
| GET    | `/`            | Home Page              |
| GET    | `/login`       | Login Page             |
| POST   | `/login`       | Authenticate User      |
| GET    | `/register`    | Registration Page      |
| POST   | `/register`    | Register a New User    |
| GET    | `/logout`      | Logout User            |
| GET    | `/create-post` | Create Post Page       |
| POST   | `/create-post` | Create a New Blog Post |
| GET    | `/edit/:id`    | Edit Post Page         |
| POST   | `/edit/:id`    | Update Blog Post       |
| POST   | `/delete/:id`  | Delete a Blog Post     |
| POST   | `/delete-user` | Delete a User Account  |

## Future Enhancements

- Add **comments & likes** on posts
- Implement **user profiles**
- Enable **post search & filtering**

## License

This project is licensed under the **MIT License**.

## Contributing

Feel free to contribute by submitting a pull request or reporting issues.

#### Happy Coding! 🚀
