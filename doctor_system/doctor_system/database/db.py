import pyodbc

def get_connection():
    conn = pyodbc.connect(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=localhost;"
        "DATABASE=clinic_db;"
        "Trusted_Connection=yes;"
        "TrustServerCertificate=yes;"
    )
    return conn