# Backend Project Setup CLI

A command-line tool for quickly generating fully structured backend projects with predefined setups.

## Features

- **Basic Setup**: Includes the folder structure, basic Express setup with `app.js`, `server.js`, `.env`, and `db.config`.
- **Advanced Setup**: Includes authentication logic, user logic, middleware, and additional security configurations.

## Installation

To install the package globally, run the following command:

```bash
npm install -g backend-project-setup-cli
```

## Usage

After installation, you can use the CLI to generate a new project with your preferred setup type.

```bash
backend-project-setup-cli <project-name>
```

You will be prompted to choose between two setup types:

1. Basic Setup – A simple structure with essential files for your Express.js backend.

2. Advanced Setup – Includes additional features like authentication, user logic, and middleware for enhanced security and functionality.

## Folder structure

# Basic Setup

The basic setup will generate the following folder structure:

/<project-name>
├── .env
├── app.js
├── server.js
├── db.config.js
├── /models
├── /controllers
└── /routes

# Advanced Setup

The advanced setup will generate the following folder structure with additional auth controller, middleware, routes, as well as user.

/<project-name>
├── .env
├── app.js
├── server.js
├── db.config.js
├── /models
└── user.model.js
├── /controllers
└── user.controller.js
├── /routes
└── user.routes.js
├── /middlewares
└── auth.middleware.js
└── /config
└── jwt.config.js

## Dependencies Installed

The following dependencies are automatically installed:

express: A fast and minimalist web framework for Node.js.

mongoose: An ODM (Object Data Modeling) library for MongoDB and Node.js.

jsonwebtoken: For creating and verifying JSON Web Tokens (JWT).

bcryptjs: For hashing passwords.

multer: A middleware for handling multipart/form-data, used for file uploads.

cloudinary: For storing files in the cloud.

dotenv: Loads environment variables from a .env file.

express-rate-limit: Middleware to limit repeated requests to public APIs.

helmet: Helps secure your Express apps by setting various HTTP headers.

hpp: Protects against HTTP Parameter Pollution attacks.

xss-clean: A middleware to sanitize user input and protect against XSS attacks.

express-mongo-sanitize: Protects against MongoDB Operator Injection.

nodemon: A tool that automatically restarts the application when file changes are detected.

express-validator: A set of middlewares for validating and sanitizing user input.

cookie-parser: Parse cookies in request headers.
