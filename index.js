#!/usr/bin/env node
import { program } from "commander";
import fs from "fs-extra";
import chalk from "chalk";
import { execSync } from "child_process";
import inquirer from "inquirer";
import { basicSetup } from "./constants/basicSetup.js";
import { advancedSetup } from "./constants/advancedSetup.js";

async function createProject(projectName) {
  const { setupType } = await inquirer.prompt([
    {
      type: "list",
      name: "setupType",
      message: "Choose the setup type:",
      choices: [
        {
          name: "Basic Setup - Includes folder structure, app.js, server.js, .env files, db.config",
          value: "basic",
        },
        {
          name: "Advanced Setup - Includes auth logic (middleware, routes, controller), user logic (model, routes, controller), and more",
          value: "advanced",
        },
      ],
    },
  ]);

  const projectStructure = setupType === "basic" ? basicSetup : advancedSetup;

  console.log(
    chalk.green(`Creating project ${projectName} with ${setupType} setup...`)
  );

  // Create main project folder and change directory into it
  fs.mkdirSync(projectName);
  process.chdir(projectName);

  // Create subfolders
  projectStructure.folders.forEach((folder) => fs.mkdirSync(folder));

  // Create files with predefined content
  for (const [filePath, content] of Object.entries(projectStructure.files)) {
    fs.outputFileSync(filePath, content.trim());
  }

  console.log(chalk.green("Project structure created successfully!"));

  // Initialize npm and install dependencies
  try {
    console.log(chalk.blue("Initializing npm and installing dependencies..."));
    execSync("npm init -y");
    execSync(
      "npm install express mongoose jsonwebtoken bcryptjs multer cloudinary dotenv express-rate-limit cors helmet hpp xss-clean express-mongo-sanitize nodemon express-validator cookie-parser"
    );
    console.log(chalk.green("Dependencies installed successfully!"));
  } catch (error) {
    console.error(
      chalk.red("Error during npm initialization or package installation"),
      error
    );
  }
}

// Command line interface setup
program
  .version("1.0.0")
  .description(
    "A CLI tool to generate fully structured Express projects with different setup options."
  )
  .argument("<project-name>", "Project name")
  .action(createProject);

program.parse(process.argv); // Parse the command line arguments
