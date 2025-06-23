# SSH Web Terminal

A simple web terminal application that allows you to establish an SSH connection from your web browser.

## Overview

`ssh-web-terminal` is a Node.js-based web application that enables users to connect to a server via SSH through a web browser and execute commands. This allows for easy server management even in environments where a dedicated SSH client is not available.

## Features

  * **Web-Based SSH Client:** Access your servers via SSH from anywhere, using only a web browser.
  * **Direct URL Access:** Each terminal session can be accessed via a unique URL. This allows you to directly open a terminal session by simply visiting the URL.
  * **Integration with Monitoring Tools:** By embedding the terminal URL into monitoring tools like Zabbix, you can instantly access a server's command line when an issue occurs, enabling rapid investigation and response.
  * **Authentication:** It includes a username and password authentication system.

## Installation and Setup

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/nullpo7z/ssh-web-terminal.git
    cd ssh-web-terminal
    ```

2.  **Install the necessary dependencies:**

    ```bash
    npm install
    ```

## Usage

1.  **Start the server:**

    ```bash
    node server.js
    ```

    or

    ```bash
    npm start
    ```

2.  **Access via web browser:**
    Open your web browser and navigate to `https://YOUR-SERVER-IP:3000`.

    default user name is `admin`, default password is `changeme`

4.  **Change the password**
    When you log in for the first time, follow the on-screen instructions to change your password.

5.  **Enter SSH credentials:**
    Register a new server by entering the server name, server address, user name, and private key on the Add Server tab.

## Features to be added in the future
  - Add multiple users 
  - Manage permissions 
  - Store and view ssh logs 
  - Transfer logs to syslog server 
  - Add sftp functionality 
  - Access via cli
