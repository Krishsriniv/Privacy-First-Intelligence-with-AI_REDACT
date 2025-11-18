# Create database

CREATE DATABASE CORTEX_AISQL_DEMO_DB;

USE DATABASE CORTEX_AISQL_DEMO_DB;;

# Example 1: Simple Sentence Redaction

SELECT
  ai_redact(
    'John Doe from Toronto is a platinum credit card holder',
    ARRAY_CONSTRUCT('NAME')
  ) AS redacted_text;

# Example 2: Combining Multiple Categories

CREATE OR REPLACE TABLE patient_notes (
    id INT,
    notes STRING
);

INSERT INTO patient_notes VALUES
(1, 'David Cooper was diagnosed with hypertension. His Birthday is 2/2/1968. his appointment is on 11/11/2026. Contact him at dcooper@example.com.'),
(2, 'Patient Maria Lopez reported migraines. Email maria_lopez@gmail.com with the report.'),
(3, 'John from Kolkata mentioned back pain and shared john_k@xyz.com for further contact');

SELECT
  id,
  ai_redact(
    notes,
    ARRAY_CONSTRUCT('NAME','EMAIL','PHONE_NUMBER','DATE_OF_BIRTH','AGE')
  ) AS redacted_notes
FROM patient_notes;

# Example 3: Redacting PII in a Table Column

# Create and load the Customer_Support_Logs table in CORTEX_AISQL_DEMO_DB.PUBLIC before running these queries.

USE DATABASE CORTEX_AISQL_DEMO_DB;

SELECT * FROM customer_support_logs;

SELECT
  ticket_id,
  ai_redact(
    customer_message,
    ARRAY_CONSTRUCT('NAME','EMAIL','PHONE_NUMBER','ADDRESS','NATIONAL_ID','PASSPORT','TAX_IDENTIFIER')
  ) AS redacted_message
FROM customer_support_logs;

# Example 4: Redacting JSON / Semi-Structured Text

USE DATABASE CORTEX_AISQL_DEMO_DB;

CREATE OR REPLACE TABLE messages (
  id INT,
  data VARIANT
);

INSERT INTO messages (id, data)
SELECT 1, PARSE_JSON('{
    "user": "Peter Paul",
    "email": "peter.p@example.com",
    "message": "Please call me at 123456789 about the delivery issue.",
    "location": {
        "street": "22 Victory St",
        "city": "Austin"
    }
}');

INSERT INTO messages (id, data)
SELECT 2, PARSE_JSON('{
    "user": "Sarah Smith",
    "email": "sarah.smith@testexample.com",
    "message": "My passport number is A1234567. Kindly verify.",
    "location": {
        "street": "745 Evergreen Terrace",
        "city": "Springfield"
    }
}');

SELECT
    id,
    ai_redact(
        data:message::string,
        ARRAY_CONSTRUCT('PHONE_NUMBER','PASSPORT','ADDRESS')
    ) AS redacted_message,
    ai_redact(
        data:email::string,
        ARRAY_CONSTRUCT('EMAIL')
    ) AS redacted_email,
    ai_redact(
        data:user::string,
        ARRAY_CONSTRUCT('NAME')
    ) AS redacted_user,
    ai_redact(
        data:location:street::string,
        ARRAY_CONSTRUCT('ADDRESS')
    ) AS redacted_street
FROM messages;

# Example 5: Creating a Redacted Table for further analytics

CREATE OR REPLACE TABLE customer_support_logs_redacted AS
SELECT
 ticket_id,
 ai_redact(
 customer_message,
 ARRAY_CONSTRUCT('NAME','EMAIL','PHONE_NUMBER','ADDRESS')
 ) AS redacted_message
FROM customer_support_logs;

# Example 6: Redaction → Summarization (Chain AI Functions)

CREATE OR REPLACE TABLE cust_complaints (
    id INT,
    message STRING
);

INSERT INTO cust_complaints (id, message) VALUES
(1, 'Hi, this is Jason Miller. I am following up about my refund request. I updated my address last month to 742 Willow Flower Drive, Austin, Texas, but the system still shows my old address from San Jose. Because of that, the refund check was mailed to the wrong place. I also updated my phone number to 123-456-7898, yet support still calls my old number. The portal is also showing my SSN 01-234-5678 as verification pendi even though I uploaded the correct documents last week. Could someone please help fix these details so my refund can be reissued? You can reach me at jason.miller@testexample.com');

SELECT
  SNOWFLAKE.CORTEX.SUMMARIZE(
    ai_redact(
      message,
      ARRAY_CONSTRUCT('NAME','EMAIL','PHONE_NUMBER','ADDRESS','NATIONAL_ID')
    )
  ) AS summary
FROM cust_complaints;

# Example 7: Role-Based Dynamic Redaction

# using Secure views

CREATE OR REPLACE VIEW customer_messages_secure AS
SELECT
    id,
    CASE 
        WHEN CURRENT_ROLE() = 'PII_ADMIN' THEN message
        ELSE ai_redact(
               message,
               ARRAY_CONSTRUCT('NAME','EMAIL','PHONE_NUMBER','ADDRESS','NATIONAL_ID')
             )
    END AS message
FROM cust_complaints;

select * from customer_messages_secure;

# using masking policy on supported regions and editions.

CREATE MASKING POLICY redact_policy AS (val STRING) RETURNS STRING ->
 CASE 
 WHEN CURRENT_ROLE() IN ('PII_ADMIN') THEN val
 ELSE ai_redact(val, ARRAY_CONSTRUCT('NAME','EMAIL','PHONE_NUMBER'))
 END;

# Example 8: Compliance & QA Checks

#Note that the Patient Notes table was created as part of example 2

SELECT
  id,
  notes AS original_text,
  ai_redact(
    notes,
    ARRAY_CONSTRUCT('NAME','EMAIL','PHONE_NUMBER')
  ) AS redacted_text
FROM patient_notes;

