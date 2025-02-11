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

express

mongoose

jsonwebtoken

bcryptjs

multer

cloudinary

dotenv

express-rate-limit

helmet

hpp

xss-clean

express-mongo-sanitize

nodemon

express-validator

cookie-parser
