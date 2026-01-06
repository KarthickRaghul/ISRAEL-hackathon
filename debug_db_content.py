
import pandas as pd
from sqlalchemy import create_engine
from config import Config

DB_URL = f"mysql+mysqlconnector://{Config.DB_USER}:{Config.DB_PASSWORD}@{Config.DB_HOST}/{Config.DB_NAME}"
engine = create_engine(DB_URL)

try:
    df = pd.read_sql("SELECT id, src_ip, dst_ip, action FROM logs ORDER BY id DESC LIMIT 5", engine)
    print("Columns:", df.columns.tolist())
    print(df.to_string())
    
    # Check types and values
    print("\nTypes:")
    print(df.dtypes)
    
    # Check for empty strings or None
    print("\nCheck first row src_ip:")
    val = df.iloc[0]['src_ip']
    print(f"Value: '{val}', Type: {type(val)}, falsy: {not val}")

except Exception as e:
    print(f"Error: {e}")
