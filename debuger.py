from app import db
from app.models import Enrollment, Course, User

# Replace 1 with actual student ID
student = User.query.filter_by(role='student').first()
if student:
    enroll_count = Enrollment.query.filter_by(student_id=student.id).count()
    print(f"Student {student.username} has {enroll_count} enrollments")
    
    # Check course-instructor relationships for these enrollments
    enrollments = Enrollment.query.filter_by(student_id=student.id).all()
    for enroll in enrollments:
        course = Course.query.get(enroll.course_id)
        print(f"Course: {course.name} | Instructor: {course.instructor or 'None'}")
        