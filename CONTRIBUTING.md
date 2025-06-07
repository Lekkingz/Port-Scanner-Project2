# Contributing to Multi-threaded Port Scanner

I welcome contributions to make this port scanner even better! Your help is greatly appreciated. Here are some guidelines to help you get started.

## How to Contribute

I encourage you to contribute through pull requests, bug reports, and feature suggestions.

### 1. Reporting Bugs

If you find a bug, please open an issue on the [GitHub Issues page] When reporting a bug, please include:
* A clear and concise description of the bug.
* Steps to reproduce the behavior (e.g., command used, target, port range).
* Expected behavior.
* Actual behavior.
* Your operating system (e.g., Linux, Windows, macOS) and Python version (`python --version`).

### 2. Suggesting Enhancements / New Features

Have an idea for a new feature or an improvement? Please open an issue on the [GitHub Issues page]. Describe your idea clearly and explain why you think it would be valuable to the project.

### 3. Contributing Code

To contribute code, please follow these steps:

1.  **Fork the Repository:** Start by forking the repository on GitHub.
    
2.  **Clone Your Fork:** Clone your forked repository to your local machine.
    
  `
3.  **Create a New Branch:** Always work on a new branch. Name your branch descriptively based on its purpose (e.g., `feature/add-service-detection`, `bugfix/fix-timeout-issue`).
    ```bash
    git checkout -b your-feature-or-bugfix-branch
    ```
4.  **Set Up Virtual Environment (Recommended):**
    ```bash
    python3 -m venv venv
    # Linux/macOS:
    source venv/bin/activate
    # Windows (Command Prompt):
    venv\Scripts\activate.bat
    # Windows (PowerShell):
    .\venv\Scripts\Activate.ps1
    ```
5.  **Install Dependencies:**
    ```bash
    pip install -e . # Installs the project in editable mode and its dependencies
    ```
6.  **Make Your Changes:** Implement your bug fix or feature.
    * Ensure your code adheres to a clean, readable style.
    * Add comments where necessary, especially for complex logic.
    * If you're adding a new feature, consider how it might be tested.
7.  **Test Your Changes:** Run the script to ensure your changes work as expected and don't introduce new bugs.
    ```bash
    python port_scanner.py <target>
    ```
8.  **Commit Your Changes:** Write clear, concise, and descriptive commit messages.
    ```bash
    git commit -m "feat: Add new feature X" # For new features
    git commit -m "fix: Resolve bug Y"      # For bug fixes
    ```
9.  **Push to Your Fork:** Push your branch to your GitHub fork.
    ```bash
    git push origin your-feature-or-bugfix-branch
    ```
10. **Open a Pull Request (PR):** Go to the original repository on GitHub, navigate to the "Pull requests" tab, and open a new Pull Request from your branch.
    * Provide a clear title and description of your changes.
    * Reference any related issues (e.g., "Closes #123" or "Fixes #456").

## Code Style

* We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code style.
* Use clear and descriptive variable and function names.
* Keep functions focused on a single task.

Thank you for contributing!
