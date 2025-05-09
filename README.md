
 Student Performance Dashboard

A web application to monitor and visualize student academic performance. It offers an intuitive interface for administrators, teachers, registrars, and students to manage and view academic data.

💻 Requirements

- Python 3.8+ – The app is built in Python; install the latest version.
- Flask – A lightweight web framework for building the application.
- Flask-Logi – Manages user authentication.
- Flask-SQLAlchemy – Handles database interactions (ORM).
- Werkzeug – Utility library that Flask depends on.
- Database – A SQL database (e.g., SQLite, PostgreSQL) for storing data; configured via SQLAlchemy.
- Other dependencies as listed in `requirements.txt`.

 Getting Started

Follow these steps to set up the project locally:

1. Clone the repository:  
   ```bash
   git clone https://github.com/Abdataa/student-performance-dashboard.git
   cd student-performance-dashboard
   ```
2. Create and activate a virtual environment:  
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```
3. Install dependencies: 
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:  
   ```bash
   python app.py 
   ```  
   The app will start on `http://localhost:5000` by default.

🛡️ User Roles

- Admin: Full access to the system. Can manage users, courses, and all settings.
- Registrar: Manages student enrollment and maintains official student records.
- Teacher: Manages classes and grades. Can enter grades and view student performance for their courses.
- Student: Views personal academic records and performance dashboards.

Contribution Workflow

To contribute code or improvements:

1. Create a branch: Checkout from `main` and create a new branch for your feature or fix.  
2. Develop your changes: Implement your feature or bug fix. Follow the project's coding conventions and write clear, concise commit messages.
3. Push to your branch:  
   ```bash
   git push -u origin your-branch-name
   ```
4. Open a Pull Request: From your branch to `main`. Include a descriptive title and details of your changes. Reference any relevant issues.
5. Review and merge: Address feedback from code reviews. Once approved, the branch can be merged into `main`.

 Important Guidelines

- Adhere to the code style: Follow PEP8 and keep the code clean and readable.
- Test your code: Write tests for new features or bug fixes whenever possible to maintain quality.
- Keep commits focused: Make atomic commits with clear messages. Rebase or squash minor commits before merging.
- Update documentation: If you add or modify features, update the documentation and comments accordingly.
- No direct pushes to `main`: Use branches and pull requests for all changes.
- Link issues: Reference any related issue IDs in your commit messages or PR descriptions for context.


