"""Add class_name column to classes table

Revision ID: 001_add_class_name
Revises: 
Create Date: 2025-09-17 17:30:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001_add_class_name'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Add the column as nullable=True first to avoid issues with existing rows
    op.add_column('classes', sa.Column('class_name', sa.String(length=160), nullable=True))
    # Update existing rows to set class_name to course_name
    op.execute(sa.text("UPDATE classes SET class_name = course_name"))
    # Alter the column to nullable=False
    op.alter_column('classes', 'class_name', nullable=False)


def downgrade():
    # Drop the column
    op.drop_column('classes', 'class_name')