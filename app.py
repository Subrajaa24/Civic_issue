# app.py

import os
import random
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, desc
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.sql import func
from sqlalchemy.exc import SQLAlchemyError

# Import PostGIS-specific types (Requires 'geoalchemy2' package)
from geoalchemy2 import Geometry 

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app) 
PORT = int(os.environ.get('PORT', 3000))

# --- Database Setup and Engine ---
# PostgreSQL connection string format: 'postgresql://user:password@host:port/dbname'
DATABASE_URL = (
    f"postgresql://{os.environ.get('DB_USER')}:"
    f"{os.environ.get('DB_PASSWORD')}@"
    f"{os.environ.get('DB_HOST')}:"
    f"{os.environ.get('DB_PORT', 5432)}/"
    f"{os.environ.get('DB_NAME')}"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Database Models (SQLAlchemy ORM) ---

STATUS_ENUM = ENUM('Pending Review', 'In Progress', 'Resolved', name='issue_status')

class Category(Base):
    __tablename__ = 'categories'
    category_id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    issues = relationship("Issue", back_populates="category")

class Issue(Base):
    __tablename__ = 'issues'
    issue_id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    category_id = Column(Integer, ForeignKey('categories.category_id'))
    category = relationship("Category", back_populates="issues")
    
    # PostGIS Geometry Type: Stores a POINT with SRID 4326 (WGS 84)
    location = Column(Geometry(geometry_type='POINT', srid=4326), nullable=False)
    
    # AI/ML Integration Fields
    severity_score = Column(Integer, default=0) # 0 (Low) to 5 (High)
    media_url = Column(String(255))
    
    status = Column(STATUS_ENUM, default='Pending Review')
    guest_email = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# --- Database Initialization (Runs on Server Startup) ---
def init_db():
    """Creates tables and ensures PostGIS extension is enabled."""
    try:
        conn = engine.raw_connection()
        cursor = conn.cursor()
        
        # Enable PostGIS (Must be done once for the database)
        cursor.execute("CREATE EXTENSION IF NOT EXISTS postgis;")
        conn.commit()
        cursor.close()
        conn.close()

        # Create all tables defined by the ORM models
        Base.metadata.create_all(bind=engine)
        
        # Insert default categories
        session = SessionLocal()
        default_categories = ['Pothole', 'Graffiti', 'Broken Streetlight', 'Illegal Dumping', 'Park Maintenance']
        for name in default_categories:
            if not session.query(Category).filter_by(name=name).first():
                session.add(Category(name=name))
        session.commit()
        session.close()
        print("Database initialized (tables and categories created/checked).")

    except SQLAlchemyError as e:
        print(f"Database initialization failed: {e}")

# Function to provide a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- ML Model Placeholders (Replace with actual ML code) ---
def run_cnn_rnn_image_analysis(media_bytes):
    """Placeholder for Hybrid CNN-RNN model inference (Image Severity)."""
    return random.randint(1, 5) 

def run_svm_nlp_text_analysis(description):
    """Placeholder for SVM-NLP model inference (Text Severity)."""
    if "emergency" in description.lower() or "critical" in description.lower(): 
        return 5
    elif "minor" in description.lower():
        return 1
    return 3


# --- API Endpoint 1: POST /api/issues (Submit a new issue) ---

@app.route('/api/issues', methods=['POST'])
def report_issue():
    data = request.json
    
    # 1. Variable Extraction (Fixes Pylance "is not defined" errors)
    try:
        title = data['title']
        description = data.get('description', '')
        category_id = int(data['category_id'])
        latitude = float(data['latitude'])
        longitude = float(data['longitude'])
        guest_email = data.get('guest_email')
        media_bytes = data.get('media_bytes') 
    except (KeyError, ValueError) as e:
        return jsonify({"error": f"Missing or invalid field: {e}"}), 400

    media_url = None

    # 2. Severity Calculation & Media Handling
    text_severity = run_svm_nlp_text_analysis(description)
    image_severity = 0
    
    if media_bytes:
        image_severity = run_cnn_rnn_image_analysis(media_bytes)
        # In a real app, media_bytes would be saved to cloud storage here.
        media_url = f"https://media.cloudstorage.com/{title.replace(' ', '_')}_{random.randint(100, 999)}.jpg" 

    overall_severity = max(text_severity, image_severity)
    
    # 3. Database Insertion
    try:
        db = next(get_db())
        
        new_issue = Issue(
            title=title,
            description=description,
            category_id=category_id,
            # PostGIS requires (Longitude Latitude) order
            location=f'POINT({longitude} {latitude})', 
            guest_email=guest_email,
            severity_score=overall_severity,
            media_url=media_url
        )
        
        db.add(new_issue)
        db.commit()
        db.refresh(new_issue)

        return jsonify({
            "message": f"Issue reported successfully! Priority: {overall_severity}",
            "issue_id": new_issue.issue_id,
            "severity_score": new_issue.severity_score
        }), 201

    except Exception as error:
        print(f"Error reporting issue: {error}")
        return jsonify({"error": f"Failed to report issue: {str(error)}"}), 500


# --- API Endpoint 2: GET /api/issues (Retrieve all issues) ---

@app.route('/api/issues', methods=['GET'])
def get_issues():
    try:
        db = next(get_db())
        
        issues_query = db.query(
            Issue.issue_id, 
            Issue.title, 
            Issue.status,
            Issue.severity_score,
            Issue.created_at,
            Issue.media_url,
            Category.name.label('category_name'),
            # Extract Lat/Lon from PostGIS geometry
            func.ST_X(Issue.location).label('longitude'), 
            func.ST_Y(Issue.location).label('latitude')
        ).join(Category).order_by(desc(Issue.severity_score), desc(Issue.created_at)).all()

        issues_list = []
        for row in issues_query:
            # Convert SQLAlchemy row object to a dictionary for JSON
            issue_dict = {
                'issue_id': row.issue_id,
                'title': row.title,
                'status': row.status,
                'severity_score': row.severity_score,
                'created_at': row.created_at.isoformat(),
                'category_name': row.category_name,
                'longitude': row.longitude,
                'latitude': row.latitude,
                'media_url': row.media_url
            }
            issues_list.append(issue_dict)

        return jsonify(issues_list), 200

    except Exception as error:
        print(f"Error retrieving issues: {error}")
        return jsonify({"error": "Failed to retrieve issues from the database."}), 500

if __name__ == '__main__':
    # Initialize DB before running the Flask server
    init_db() 
    print(f"Flask Server running on http://localhost:{PORT}")
    app.run(host='0.0.0.0', port=PORT)