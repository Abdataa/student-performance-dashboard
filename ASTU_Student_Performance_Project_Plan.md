
# 🧠 AI-Powered Student Performance Dashboard – Project Development Plan

## ✅ Phase 1: Critical Work (60%) – Group Leader (You)

### 1. Machine Learning Models (✅ Completed)
- [x] Grade Prediction Model (`student_performance_predictor_model.joblib`)
- [x] At-Risk Classification Model (`at_risk_classifier_model.joblib`)
- [x] Rule-Based Recommendation Logic

### 2. Model Refinement (if needed)
- [x] Retrain the predictor model using selected subset features for better deployment performance.
- [x] Save and test updated model.

### 3. Backend Integration (Flask API)
- [ ] Load all 3 models into `app.py`
- [ ] Create API endpoints:
  - `/predict-grade`
  - `/check-risk`
  - `/recommendation`
- [ ] Handle preprocessing (label encoding, feature selection)
- [ ] Return JSON or render results in templates
- [ ] Accept form input and CSV files

### 4. Teacher Dashboard (New Feature)
- [ ] Login functionality for teachers
- [ ] Upload student grades & attendance via CSV
- [ ] Visualize student-wise or course-wise trends

### 5. Student Portal Logic
- [ ] Student login + registration logic
- [ ] New students:
  - Upload ID, transcripts, and personal details
  - Status = "Pending Approval" by Registrar
- [ ] Returning students:
  - Log in, access dashboard, and register for semester
- [ ] Submit academic info:
  - View predicted grade
  - Risk status
  - Recommendations
  - Attendance visualization

### 6. Export Feature
- [ ] Export results (grade + feedback) as PDF

### 7. Testing and Version Control
- [ ] Run manual tests on the core flows
- [ ] Commit and push finalized working version to GitHub

---

## 👥 Phase 2: Group Work (40%) – Group A, B, C

### Group A: Student Input Interface (3 Members)
- [ ] Build form for student input using HTML/Bootstrap
- [ ] Create CSV Upload field
- [ ] Connect form to Flask backend

### Group B: Admin Panel + Data Visualization (3 Members)
- [ ] Admin login functionality
- [ ] Upload batch CSV for multiple students
- [ ] Show batch stats:
  - Average grade
  - % at-risk students
  - Most failed subjects

### Group C: UI Polishing & Export Integration (1 Member)
- [ ] Improve frontend look & feel
- [ ] Support PDF export for student report

---

## 🧱 Additional Features to Implement

### 🔐 User Roles & Access Control
- [ ] Define roles:
  - Admin
  - Teacher
  - Student
  - Registrar
- [ ] Restrict views & actions based on role

### 🗃️ Database Integration
- [ ] Use SQLite/PostgreSQL to store:
  - Users (students, teachers, registrar)
  - Grades
  - Attendance records
  - Semester registrations

### 🔔 Notifications System
- [ ] When student registers → Registrar gets notification
- [ ] Upon approval → Student sees confirmation notification

### 📊 Student Dashboard Enhancements
- [ ] Track performance over semesters
- [ ] Show trends and improvements over time (if historical data exists)

### 🔒 Security
- [ ] Use hashed passwords (e.g., `werkzeug.security`)
- [ ] Implement session-based login with expiry
- [ ] Protect all API endpoints from unauthorized access

---

## 🧪 Final Touches (Leader or All)
- [ ] Write full documentation (`README.md`, `INSTALL.md`)
- [ ] Clean and organize folder structure
- [ ] Final push and GitHub merge
- [ ] Prepare for presentation/demo

---

Let’s build something impactful for ASTU! 🚀
