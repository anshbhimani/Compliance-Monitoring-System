from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class CompliancePackage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    scripts = db.Column(db.JSON)  # List of scripts in the package

class ComplianceResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    script_name = db.Column(db.String(100))
    result = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime)
