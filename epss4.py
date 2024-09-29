import psycopg2
import json
import logging

class VulnUpdater:
    def __init__(self, json_file_path, db_config):
        self.json_file_path = json_file_path
        self.db_config = db_config
        logging.basicConfig(filename='PatrowlHearsData-main/EPSS/data/logfile.log', level=logging.INFO, 
                            format='%(asctime)s %(levelname)s: %(message)s')

    def fetch_json_data(self):
        try:
            logging.info(f"Fetching data from JSON file: {self.json_file_path}")
            with open(self.json_file_path, 'r') as file:
                json_data = json.load(file)
            logging.info("JSON data fetched successfully.")
            logging.info(f"JSON data structure: {list(json_data.keys())}")  # Log keys for debugging
            return json_data
        except Exception as e:
            logging.error(f"Error fetching JSON data: {e}")
            raise

    def ensure_column_exists(self):
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            logging.info("Checking if epss_score column exists.")

            # Check if the column exists
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns 
                WHERE table_name = 'vulns' AND column_name = 'epss_score';
            """)
            exists = cursor.fetchone()

            # If the column doesn't exist, create it
            if not exists:
                logging.info("epss_score column does not exist. Creating it.")
                cursor.execute("ALTER TABLE vulns ADD COLUMN epss_score NUMERIC;")
                conn.commit()
                logging.info("epss_score column created successfully.")
            else:
                logging.info("epss_score column already exists.")
            
            cursor.close()
            conn.close()

        except Exception as e:
            logging.error(f"Error ensuring epss_score column exists: {e}")
            raise

    def update_table(self, json_data):
        try:
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            logging.info("Connected to the PostgreSQL database.")

            epss_data = json_data.get('epss', {})

            for cveid, data in epss_data.items():
                epss_score = data.get('epss', None)
                logging.info(f"Processing CVE ID: {cveid} with EPSS score: {epss_score}")

                if epss_score is None:
                    logging.warning(f"Skipping CVE ID: {cveid} because epps score is None.")
                    continue

                cursor.execute("""
                                UPDATE vulns
                                SET epss_score = %s
                                WHERE cveid = %s
                                """, (float(epss_score), cveid))
                logging.info(f"Updated {cursor.rowcount} rows for CVE ID: {cveid}")

                if cursor.rowcount == 0:
                    logging.warning(f"No rows updated for CVE ID: {cveid}")

            conn.commit()
            logging.info("Changes committed.")
            cursor.close()
            conn.close()
            logging.info("Database connection closed.")
        except Exception as e:
            logging.error(f"Error updating the table: {e}")
            raise

    def run_update(self):
        try:
            logging.info("Starting the CVE update process.")
            self.ensure_column_exists()  # Ensure the column is created before updating
            json_data = self.fetch_json_data()
            self.update_table(json_data)
            logging.info("CVE data update completed.")
        except Exception as e:
            logging.error(f"Failed to complete update: {e}")

if __name__ == "__main__":
    json_file_path = "PatrowlHearsData-main/EPSS/data/epss-previous.json"  # Path to the JSON file on the server
    db_config = {
        "host": "172.18.0.3",  # PostgreSQL container name or IP
        "port": 5432,                     # PostgreSQL port
        "database": "patrowlhears_db",     # Correct database name
        "user": "patrowlhears",                # PostgreSQL username
        "password": "patrowlhears"             # PostgreSQL password
    }

    updater = VulnUpdater(json_file_path, db_config)

    # Run the update once and then exit
    updater.run_update()