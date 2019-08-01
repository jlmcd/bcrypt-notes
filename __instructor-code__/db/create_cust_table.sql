CREATE TABLE customer (
  cust_id SERIAL PRIMARY KEY,
  email VARCHAR(180),
  hash_value TEXT
)