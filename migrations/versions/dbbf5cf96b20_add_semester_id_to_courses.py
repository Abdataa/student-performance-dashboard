"""Add semester_id to courses

Revision ID: dbbf5cf96b20
Revises: 19831a1d7589
Create Date: 2025-05-14 04:10:10.140637

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dbbf5cf96b20'
down_revision = '19831a1d7589'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('courses', schema=None) as batch_op:
        batch_op.add_column(sa.Column('semester_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(  # Add a constraint name here
            "fk_courses_semester_id",  # Name for the foreign key constraint
            'semesters', 
            ['semester_id'], 
            ['id']
        )

    # ### end Alembic commands ###


def downgrade():
    with op.batch_alter_table('courses', schema=None) as batch_op:
        batch_op.drop_constraint("fk_courses_semester_id", type_='foreignkey')
        batch_op.drop_column('semester_id')

    # ### end Alembic commands ###
