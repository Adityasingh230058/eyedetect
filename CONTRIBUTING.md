# Contributing to eyedetect

Thank you for contributing to **eyedetect**!

## 🛠️ Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/eyedetect.git
   cd eyedetect
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install pytest pytest-cov
   ```

3. **Run the test suite:**
   ```bash
   pytest -v tests/
   ```

## 📋 Pull Request Guidelines

- Ensure all detection rules have test coverage under `tests/`.
- Adhere to the MITRE ATT&CK taxonomy standards.
- Use descriptive commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) specification.
